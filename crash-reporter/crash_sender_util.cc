// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_sender_util.h"

#include <inttypes.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <algorithm>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <base/check.h>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <brillo/flag_helper.h>
#include <brillo/http/http_proxy.h>
#include <brillo/http/http_transport.h>
#include <brillo/http/http_utils.h>
#include <brillo/mime_utils.h>
#include <brillo/variant_dictionary.h>
#include <chromeos/dbus/service_constants.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/crash_sender.pb.h"
#include "crash-reporter/crash_sender_paths.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

namespace util {

namespace {

constexpr char kAlreadyUploadedExt[] = ".alreadyuploaded";

// Keys used in uploads.log file. (All timestamps are measured in seconds.)
constexpr char kJsonLogKeyUploadId[] = "upload_id";
constexpr char kJsonLogKeyUploadTime[] = "upload_time";
constexpr char kJsonLogKeyLocalId[] = "local_id";
constexpr char kJsonLogKeyCaptureTime[] = "capture_time";
constexpr char kJsonLogKeyState[] = "state";
constexpr char kJsonLogKeySource[] = "source";

// Keys used in CrashDetails::metadata.
constexpr char kMetadataKeyCaptureTimeMillis[] = "upload_var_reportTimeMillis";
constexpr char kMetadataKeySource[] = "exec_name";
constexpr char kHwTestSuiteRun[] = "upload_var_hwtest_suite_run";
constexpr char kHwTestSenderUpload[] = "upload_var_hwtest_sender_direct";

// Values used for kJsonLogKeySource.
constexpr char kMetadataValueRedacted[] = "REDACTED";

// Must match testModeSuccessful in the tast-test chrome_crash_loop.go.
constexpr char kTestModeSuccessful[] =
    "Test Mode: Logging success and exiting instead of actually uploading";

// UMA metrics to track crash removal attempts and failures.
constexpr char kUMAFailedCrashRemoval[] = "Crash.Sender.FailedCrashRemoval";
constexpr char kUMAAttemptedCrashRemoval[] =
    "Crash.Sender.AttemptedCrashRemoval";

// UMA enum to track reasons crash_sender attempts to delete a crash.
constexpr char kCrashSenderRemoveHistName[] =
    "Platform.CrOS.CrashSenderRemoveReason";

}  // namespace

void ParseCommandLine(int argc,
                      const char* const* argv,
                      CommandLineFlags* flags) {
  DEFINE_int32(max_spread_time, kMaxSpreadTimeInSeconds,
               "Max time in secs to sleep before sending (0 to send now)");
  DEFINE_string(crash_directory, "",
                "If set, upload only crashes in this directory.");
  const std::string ignore_rate_limits_description = base::StringPrintf(
      "Ignore normal limit of %d crash uploads per day", kMaxCrashRate);
  DEFINE_bool(ignore_rate_limits, false,
              ignore_rate_limits_description.c_str());
  const std::string ignore_hold_off_time_description = base::StringPrintf(
      "Assume all crash reports are completely written to disk. Do not "
      "wait %" PRId64 " seconds after meta file is written to start sending.",
      kMaxHoldOffTime.InSeconds());
  DEFINE_bool(ignore_hold_off_time, false,
              ignore_hold_off_time_description.c_str());
  DEFINE_bool(dev, false,
              "Send crash reports regardless of image/build type "
              "and upload them to the staging server instead.");
  DEFINE_bool(ignore_pause_file, false,
              "Ignore the existence of the pause file and run anyways");
  DEFINE_bool(test_mode, false,
              "Do not upload crashes; instead, log a special message if the "
              "crash is valid. Used by tast test ChromeCrashLoop.");
  DEFINE_bool(upload_old_reports, false,
              "If set, ignore the timestamp check and upload older reports.");
  DEFINE_bool(force_upload_on_test_images, false,
              "If set, upload even on test images. Still respects consent. "
              "(Use either the mock-consent file or normal consent settings.)");

  brillo::FlagHelper::Init(argc, argv, "Chromium OS Crash Sender");
  if (FLAGS_max_spread_time < 0) {
    LOG(ERROR) << "Invalid value for max spread time: "
               << FLAGS_max_spread_time;
    exit(EXIT_FAILURE);
  }
  flags->max_spread_time = base::TimeDelta::FromSeconds(FLAGS_max_spread_time);
  flags->crash_directory = FLAGS_crash_directory;
  flags->ignore_rate_limits = FLAGS_ignore_rate_limits;
  flags->ignore_hold_off_time = FLAGS_ignore_hold_off_time;
  flags->allow_dev_sending = FLAGS_dev;
  flags->ignore_pause_file = FLAGS_ignore_pause_file;
  flags->test_mode = FLAGS_test_mode;
  flags->upload_old_reports = FLAGS_upload_old_reports;
  flags->force_upload_on_test_images = FLAGS_force_upload_on_test_images;
  if (flags->test_mode) {
    // The pause file is intended to pause the cronjob crash_sender during
    // tests, not the crash_sender invoked by the test code.
    flags->ignore_pause_file = true;
  }
}

bool DoesPauseFileExist() {
  return base::PathExists(paths::Get(paths::kPauseCrashSending));
}

base::FilePath GetBasePartOfCrashFile(const base::FilePath& file_name) {
  std::vector<std::string> components;
  file_name.GetComponents(&components);

  std::vector<std::string> parts = base::SplitString(
      components.back(), ".", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() < 4) {
    LOG(ERROR) << "Unexpected file name format: " << file_name.value();
    return file_name;
  }

  // We temporarily must support two filename formats:
  // foo.20201116.172933.1337.log AND
  // foo.20201116.172933.12345.1337.log.
  // The new format will roll out in M89, so we can remove this check and
  // support only the new format once both:
  // 1) M89 is more than six months old.
  // 2) LTS releases are at M89 or later.
  // TODO(https://crbug.com/1150566): remove this check.
  // Check if this is the latter case by seeing if the 5th component (index 4)
  // is all numbers
  if (parts.size() > 5 &&
      parts[4].find_first_not_of("0123456789") == std::string::npos) {
    parts.resize(5);
  } else {
    parts.resize(4);
  }
  const std::string base_name = base::JoinString(parts, ".");

  if (components.size() == 1)
    return base::FilePath(base_name);
  return file_name.DirName().Append(base_name);
}

void RemoveOrphanedCrashFiles(const base::FilePath& crash_dir) {
  base::FileEnumerator iter(crash_dir, true /* recursive */,
                            base::FileEnumerator::FILES, "*");
  for (base::FilePath file = iter.Next(); !file.empty(); file = iter.Next()) {
    // Get the meta data file path.
    const base::FilePath meta_file =
        base::FilePath(GetBasePartOfCrashFile(file).value() + ".meta");

    // Check how old the file is.
    base::File::Info info;
    if (!base::GetFileInfo(file, &info)) {
      PLOG(WARNING) << "Failed to get file info: " << file.value();
      continue;
    }
    base::TimeDelta delta = base::Time::Now() - info.last_modified;

    if (!base::PathExists(meta_file) && delta.InHours() >= 24) {
      LOG(INFO) << "Removing old orphaned file: " << file.value();
      if (!base::DeleteFile(file))
        PLOG(WARNING) << "Failed to remove " << file.value();
    }
  }
}

void SortReports(std::vector<MetaFile>* reports) {
  std::sort(reports->begin(), reports->end(),
            [](const MetaFile& m1, const MetaFile& m2) {
              // Send older reports first to avoid starvation if there is a
              // constant stream of crashes (that is, if thing A is producing
              // crash reports constantly, and thing B produces one crash
              // report, make sure thing B's crash report gets sent eventually.)
              return m1.second.last_modified < m2.second.last_modified;
            });
}

std::vector<base::FilePath> GetMetaFiles(const base::FilePath& crash_dir) {
  std::vector<base::FilePath> meta_files;
  if (!base::DirectoryExists(crash_dir)) {
    // Directory not existing is not an error.
    return meta_files;
  }

  base::FileEnumerator iter(crash_dir, false /* recursive */,
                            base::FileEnumerator::FILES, "*.meta");
  std::vector<std::pair<base::Time, base::FilePath>> time_meta_pairs;
  for (base::FilePath file = iter.Next(); !file.empty(); file = iter.Next()) {
    base::File::Info info;
    if (!base::GetFileInfo(file, &info)) {
      PLOG(WARNING) << "Failed to get file info: " << file.value();
      continue;
    }
    time_meta_pairs.push_back(std::make_pair(info.last_modified, file));
  }
  std::sort(time_meta_pairs.begin(), time_meta_pairs.end());

  for (const auto& pair : time_meta_pairs)
    meta_files.push_back(pair.second);
  return meta_files;
}

bool IsAlreadyUploaded(const base::FilePath& meta_file) {
  return base::PathExists(meta_file.ReplaceExtension(kAlreadyUploadedExt));
}

bool IsTimestampNewEnough(const base::FilePath& timestamp_file) {
  const base::Time threshold =
      base::Time::Now() - base::TimeDelta::FromHours(24);

  base::File::Info info;
  if (!base::GetFileInfo(timestamp_file, &info)) {
    PLOG(ERROR) << "Failed to get file info: " << timestamp_file.value();
    return false;
  }

  return threshold < info.last_modified;
}

bool IsBelowRate(const base::FilePath& timestamps_dir,
                 int max_crash_rate,
                 int max_crash_bytes) {
  // If we can't get a size for one of our uploads, use this as a size. It's
  // an overestimate, but it ensures that when a user upgrades from a previous
  // version of the code to this version, we don't send a huge batch of reports
  // because the previous version didn't write out sizes.
  const int kGuesstimateBytes = util::kDefaultMaxUploadBytes;

  // Count the number of timestamp files, that were written in the past 24
  // hours. Remove files that are older. Each file that exists should contain
  // a SendRecord protobuf giving the number of bytes used for that send; add
  // them up.
  int current_rate = 0;
  int current_bytes = 0;
  base::FileEnumerator iter(timestamps_dir, false /* recursive */,
                            base::FileEnumerator::FILES, "*");
  for (base::FilePath file = iter.Next(); !file.empty(); file = iter.Next()) {
    if (IsTimestampNewEnough(file)) {
      ++current_rate;
      std::string serialized;
      if (!base::ReadFileToString(file, &serialized)) {
        PLOG(WARNING) << "Unable to read timestamp file at " << file.value();
        // Keep going without reading the file; what else can we do? If we
        // really get a file with bad permissions, we don't want to stop ever
        // sending crashes from this computer, so we shouldn't return false.
        // But do add something to current_bytes to avoid uploading an unlimited
        // number of reports if this happens to all our files.
        current_bytes += kGuesstimateBytes;
        continue;
      }

      crash::SendRecord previous_send;
      if (!previous_send.ParseFromString(serialized)) {
        LOG(WARNING) << "Could not parse " << file.value();
        current_bytes += kGuesstimateBytes;
        continue;
      }

      if (previous_send.size() <= 0) {
        // Zero is not a realistic size for the upload, so don't believe it.
        // Probably from a previous version of the code that didn't write out
        // the sizes. proto3 will read an empty file as "all fields are zero".
        LOG(WARNING) << "Previous upload size was " << previous_send.size()
                     << "; ignoring and guessing " << kGuesstimateBytes;
        current_bytes += kGuesstimateBytes;
        continue;
      }
      current_bytes += previous_send.size();
    } else {
      if (!base::DeleteFile(file))
        PLOG(WARNING) << "Failed to remove old report " << file.value();
    }
  }
  LOG(INFO) << "Current send rate: " << current_rate << " sends and "
            << current_bytes << " bytes/24hrs";

  // We allow either condition independently; see comments around
  // kMaxCrashBytes. Therefore, we use || instead of the more common &&.
  return current_rate < max_crash_rate || current_bytes < max_crash_bytes;
}

void RecordSendAttempt(const base::FilePath& timestamps_dir, int bytes) {
  if (!base::CreateDirectory(timestamps_dir)) {
    PLOG(ERROR) << "Failed to create a timestamps directory: "
                << timestamps_dir.value();
    return;
  }

  base::FilePath temp_file_path;
  base::ScopedFILE temp_file(
      base::CreateAndOpenTemporaryStreamInDir(timestamps_dir, &temp_file_path));
  if (temp_file == nullptr) {
    PLOG(ERROR) << "Failed to create a file in " << timestamps_dir.value();
  } else {
    crash::SendRecord record;
    record.set_size(bytes);
    std::string serialized;
    record.SerializeToString(&serialized);
    fwrite(serialized.c_str(), 1, serialized.size(), temp_file.get());
  }
}

Sender::Sender(std::unique_ptr<MetricsLibraryInterface> metrics_lib,
               std::unique_ptr<base::Clock> clock,
               const Sender::Options& options)
    : SenderBase(std::move(clock), options),
      metrics_lib_(std::move(metrics_lib)),
      shill_proxy_(options.shill_proxy),
      form_data_boundary_(options.form_data_boundary),
      always_write_uploads_log_(options.always_write_uploads_log),
      max_crash_rate_(options.max_crash_rate),
      max_crash_bytes_(options.max_crash_bytes),
      max_spread_time_(options.max_spread_time),
      allow_dev_sending_(options.allow_dev_sending),
      test_mode_(options.test_mode),
      upload_old_reports_(options.upload_old_reports),
      force_upload_on_test_images_(options.force_upload_on_test_images) {}

bool Sender::HasCrashUploadingConsent() {
  if (util::HasMockConsent()) {
    return true;
  }

  return metrics_lib_->AreMetricsEnabled();
}

bool Sender::IsSafeDeviceCoredump(const CrashInfo& info) {
  std::string value;
  if (!info.metadata.GetString("exec_name", &value))
    return false;
  return value == "devcoredump_msm" || value == "devcoredump_qcom-venus";
}

SenderBase::Action Sender::ChooseAction(const base::FilePath& meta_file,
                                        std::string* reason,
                                        CrashInfo* info) {
  if (!IsMock() && !IsOfficialImage() && !allow_dev_sending_ && !test_mode_) {
    *reason = "Not an official OS version";
    RecordCrashRemoveReason(kNotOfficialImage);
    return kRemove;
  }

  // HasCrashUploadingConsent() returns false in guest mode, thus IsGuestMode()
  // should be checked first (otherwise, all crash files are deleted in guest
  // mode).
  //
  // Note that this check is slightly racey, but should be rare enough for us
  // not to care:
  //
  // - crash_sender checks IsGuestMode() and it returns false
  // - User logs in to guest mode
  // - crash_sender checks HasCrashUploadingConsent() and it's now false
  // - Reports are deleted
  if (metrics_lib_->IsGuestMode()) {
    *reason = "Crash sending delayed due to guest mode";
    return kIgnore;
  }
  if (!HasCrashUploadingConsent()) {
    *reason = "Crash reporting is disabled";
    // Note that this will probably not actually be sent (since there's no
    // consent). Record it for completion and in case the user later enables
    // metrics consent.
    RecordCrashRemoveReason(kNoMetricsConsent);
    return kRemove;
  }

  bool allow_old_os_timestamps =
      allow_dev_sending_ || test_mode_ || upload_old_reports_;

  std::unique_ptr<util::ScopedProcessingFile> f;
  SenderBase::Action act = EvaluateMetaFileMinimal(
      meta_file, allow_old_os_timestamps, reason, info, &f);

  // Always set these tags on test images for easier filtering in dashboards.
  if (force_upload_on_test_images_) {
    info->metadata.SetString(kHwTestSuiteRun, "true");
    info->metadata.SetString(kHwTestSenderUpload, "true");
  }

  if (act != kSend) {
    return act;
  }

  if (IsAlreadyUploaded(meta_file)) {
    *reason = "Removing already-uploaded crash";
    RecordCrashRemoveReason(kAlreadyUploaded);
    return kRemove;
  }

  if (info->payload_kind == "devcore" && !IsDeviceCoredumpUploadAllowed() &&
      !IsSafeDeviceCoredump(*info)) {
    *reason = "Device coredump upload not allowed";
    return kIgnore;
  }

  return kSend;
}

void Sender::RemoveAndPickCrashFiles(const base::FilePath& crash_dir,
                                     std::vector<MetaFile>* to_send) {
  std::vector<base::FilePath> meta_files = GetMetaFiles(crash_dir);

  for (const auto& meta_file : meta_files) {
    LOG(INFO) << "Checking metadata: " << meta_file.value();

    std::string reason;
    CrashInfo info;
    switch (ChooseAction(meta_file, &reason, &info)) {
      case kRemove:
        LOG(INFO) << "Removing: " << reason;
        RemoveReportFiles(meta_file);
        break;
      case kIgnore:
        LOG(INFO) << "Ignoring: " << reason;
        break;
      case kSend:
        to_send->push_back(std::make_pair(meta_file, std::move(info)));
        break;
      default:
        NOTREACHED();
    }
  }
}

void Sender::SendCrashes(const std::vector<MetaFile>& crash_meta_files) {
  if (crash_meta_files.empty())
    return;

  std::string client_id = GetClientId();

  base::File lock(AcquireLockFileOrDie());
  for (const auto& pair : crash_meta_files) {
    const base::FilePath& meta_file = pair.first;
    const CrashInfo& info = pair.second;
    LOG(INFO) << "Evaluating crash report: " << meta_file.value();

    base::TimeDelta sleep_time;
    if (!GetSleepTime(meta_file, max_spread_time_, hold_off_time_,
                      &sleep_time)) {
      LOG(WARNING) << "Failed to compute sleep time for " << meta_file.value();
      continue;
    }

    LOG(INFO) << "Scheduled to send in " << sleep_time.InSeconds() << "s";
    lock.Close();  // Don't hold lock during sleep.
    if (!IsMock()) {
      base::PlatformThread::Sleep(sleep_time);
    } else if (!sleep_function_.is_null()) {
      sleep_function_.Run(sleep_time);
    }

    lock = AcquireLockFileOrDie();

    {
      // Mark the crash as being processed so that if we crash, we don't try to
      // send the crash again.
      // This is in a scope so that RemoveReportFiles doesn't try to remove
      // the .processing file (causing a LOG(ERROR) in the ScopedProcessingFile
      // destructor).
      ScopedProcessingFile processing(meta_file);

      // This should be checked inside of the loop, since the device can disable
      // metrics while sending crash reports with an interval up to
      // max_spread_time_ between sends. We only need to check if metrics are
      // enabled and not guest mode because in guest mode, it always indicates
      // that metrics are disabled.
      if (!HasCrashUploadingConsent()) {
        LOG(INFO) << "Metrics disabled or guest mode entered, delaying crash "
                  << "sending";
        return;
      }

      // User-specific crash reports become inaccessible if the user signs out
      // while sleeping, thus we need to check if the metadata is still
      // accessible.
      if (!base::PathExists(meta_file)) {
        LOG(INFO) << "Metadata is no longer accessible: " << meta_file.value();
        continue;
      }

      const base::FilePath timestamps_dir =
          paths::Get(paths::kTimestampsDirectory);
      if (!IsBelowRate(timestamps_dir, max_crash_rate_, max_crash_bytes_)) {
        LOG(WARNING) << "Cannot send more crashes. Sending "
                     << meta_file.value()
                     << " would exceed the max daily rate of "
                     << max_crash_rate_ << " crashes and " << max_crash_bytes_
                     << " bytes";
        return;
      }

      // If we are offline, then don't try to send any crashes.
      if (!IsMock() && !IsNetworkOnline()) {
        LOG(INFO) << "Stopping crash sending; network is offline";
        return;
      }

      const CrashDetails details = {
          .meta_file = meta_file,
          .payload_file = info.payload_file,
          .payload_kind = info.payload_kind,
          .client_id = client_id,
          .metadata = info.metadata,
      };
      Sender::CrashRemoveReason result = RequestToSendCrash(details);
      if (SenderBase::CrashRemoveReason::kRetryUploading == result) {
        LOG(WARNING) << "Failed to send " << meta_file.value()
                     << ", not removing; will retry later";
        continue;
      }
      if (SenderBase::CrashRemoveReason::kFinishedUploading == result) {
        LOG(INFO) << "Successfully sent crash " << meta_file.value()
                  << " and removing.";
      } else {
        LOG(WARNING) << "Failed to send " << meta_file.value()
                     << " due to error code " << result << ". Removing";
      }
      RecordCrashRemoveReason(result);
      RemoveReportFiles(meta_file);
    }
  }
}

std::unique_ptr<brillo::http::FormData> Sender::CreateCrashFormData(
    const CrashDetails& details, std::string* product_name_out) {
  std::unique_ptr<brillo::http::FormData> form_data =
      std::make_unique<brillo::http::FormData>(form_data_boundary_);

  FullCrash crash = ReadMetaFile(details);

  form_data->AddTextField("exec_name", crash.exec_name);
  form_data->AddTextField("board", crash.board);
  form_data->AddTextField("hwclass", crash.hwclass);
  form_data->AddTextField("prod", crash.prod);
  form_data->AddTextField("ver", crash.ver);

  if (!crash.sig.empty()) {
    form_data->AddTextField("sig", crash.sig);
    form_data->AddTextField("sig2", crash.sig);
  }

  const std::string& payload_name = crash.payload.first;
  const base::FilePath& payload_path = crash.payload.second;
  brillo::ErrorPtr file_error;
  if (!form_data->AddFileField(payload_name, payload_path, {}, &file_error)) {
    LOG(ERROR) << "Failed adding payload file (name: " << payload_name
               << ", path: " << payload_path.value()
               << ") as attachment: " << file_error->GetMessage();
    return nullptr;
  }

  for (const auto& pair : crash.key_vals) {
    form_data->AddTextField(pair.first, pair.second);
  }

  for (const auto& pair : crash.files) {
    const std::string& name = pair.first;
    const base::FilePath& path = pair.second;
    brillo::ErrorPtr file_error;
    if (base::PathExists(path) &&
        !form_data->AddFileField(name, path, {}, &file_error)) {
      LOG(ERROR) << "Failed adding file (name: " << name
                 << ", path: " << path.value()
                 << ") as attachment: " << file_error->GetMessage();
    }
  }

  if (!crash.image_type.empty())
    form_data->AddTextField("image_type", crash.image_type);

  if (!crash.boot_mode.empty())
    form_data->AddTextField("boot_mode", crash.boot_mode);

  if (!crash.error_type.empty())
    form_data->AddTextField("error_type", crash.error_type);

  LOG(INFO) << "Sending crash:";
  if (crash.prod != kChromeOsProduct)
    LOG(INFO) << "  Sending crash report on behalf of " << crash.prod;
  LOG(INFO) << "  Metadata: " << details.meta_file.value() << " ("
            << details.payload_kind << ")";
  LOG(INFO) << "  Payload: " << details.payload_file.value();
  LOG(INFO) << "  Version: " << crash.ver;
  if (!crash.image_type.empty())
    LOG(INFO) << "  Image type: " << crash.image_type;
  if (!crash.boot_mode.empty())
    LOG(INFO) << "  Boot mode: " << crash.boot_mode;
  if (IsMock()) {
    LOG(INFO) << "  Product: " << crash.prod;
    LOG(INFO) << "  URL: " << kReportUploadProdUrl;
    LOG(INFO) << "  Board: " << crash.board;
    LOG(INFO) << "  HWClass: " << crash.hwclass;
    if (!crash.sig.empty())
      LOG(INFO) << "  sig: " << crash.sig;
  }

  LOG(INFO) << "  Exec name: " << crash.exec_name;
  if (!crash.error_type.empty())
    LOG(INFO) << "  Error type: " << crash.error_type;

  form_data->AddTextField("guid", crash.guid);

  if (product_name_out)
    *product_name_out = crash.prod;

  return form_data;
}

std::shared_ptr<brillo::http::Transport> Sender::GetTransport() {
  if (proxy_servers_.empty() || proxy_servers_[0] == "direct://") {
    return brillo::http::Transport::CreateDefault();
  } else {
    return brillo::http::Transport::CreateDefaultWithProxy(proxy_servers_[0]);
  }
}

void Sender::RemoveReportFiles(const base::FilePath& meta_file) {
  if (meta_file.Extension() != ".meta") {
    LOG(ERROR) << "Not a meta file: " << meta_file.value();
    return;
  }
  RecordCrashRemoveReason(kTotalRemoval);

  const std::string pattern =
      meta_file.BaseName().RemoveExtension().value() + ".*";

  if (!metrics_lib_->SendCrosEventToUMA(kUMAAttemptedCrashRemoval)) {
    LOG(WARNING) << "Failed to record crash removal attempt in UMA";
  }
  base::FileEnumerator iter(meta_file.DirName(), false /* recursive */,
                            base::FileEnumerator::FILES, pattern);
  for (base::FilePath file = iter.Next(); !file.empty(); file = iter.Next()) {
    if (!base::DeleteFile(file)) {
      PLOG(WARNING) << "Failed to remove " << file.value();
      // We may have failed to remove the file due to incorrect selinux config
      // on the directory. However, we may still be able to add files to it,
      // so mark the crash as uploaded to prevent uploading it again.
      // See https://crbug.com/1060019.
      if (file.Extension() == ".meta") {
        if (!metrics_lib_->SendCrosEventToUMA(kUMAFailedCrashRemoval)) {
          LOG(WARNING) << "Further, couldn't record UMA event for failure";
        }
        // TODO(mutexlox): This will only help in narrow circumstances; for
        // instance it will not help if unix permissions on the directory don't
        // let the write happen. Use a different directory for these so that we
        // can write it if this directory is unwriteable.
        base::File f(meta_file.ReplaceExtension(kAlreadyUploadedExt),
                     base::File::FLAG_CREATE | base::File::FLAG_WRITE);
        if (!f.IsValid()) {
          LOG(ERROR) << "Failed to mark crash as uploaded";
        }
      }
    }
  }
}

void Sender::RecordCrashRemoveReason(SenderBase::CrashRemoveReason reason) {
  metrics_lib_->SendEnumToUMA(kCrashSenderRemoveHistName, reason,
                              kSendReasonCount);
}

std::unique_ptr<base::Value> Sender::CreateJsonEntity(
    const std::string& report_id,
    const std::string& product_name,
    const CrashDetails& details) {
  auto root_dict = std::make_unique<base::Value>(base::Value::Type::DICTIONARY);

  int64_t timestamp = (base::Time::Now() - base::Time::UnixEpoch()).InSeconds();
  root_dict->SetKey(kJsonLogKeyUploadTime,
                    base::Value(std::to_string(timestamp)));

  root_dict->SetKey(kJsonLogKeyUploadId, base::Value(report_id));
  root_dict->SetKey(kJsonLogKeyLocalId, base::Value(product_name));

  // The |capture_timestamp| should be converted from milliseconds to seconds.
  std::string capture_timestamp;
  int64_t capture_timestamp_millis;
  if (details.metadata.GetString(kMetadataKeyCaptureTimeMillis,
                                 &capture_timestamp) &&
      base::StringToInt64(capture_timestamp, &capture_timestamp_millis)) {
    root_dict->SetKey(
        kJsonLogKeyCaptureTime,
        base::Value(std::to_string(capture_timestamp_millis / 1000)));
  }

  // The state value is always same as
  // UploadList::UploadInfo::State::Uploaded.
  root_dict->SetKey(kJsonLogKeyState, base::Value(3));

  std::string source;
  if (details.metadata.GetString(kMetadataKeySource, &source)) {
    // Hide the real source to avoid privacy concern if it is not a system
    // crash.
    if (!paths::Get(paths::kSystemCrashDirectory).IsParent(details.meta_file))
      source = kMetadataValueRedacted;
    root_dict->SetKey(kJsonLogKeySource, base::Value(source));
  }

  return root_dict;
}

SenderBase::CrashRemoveReason Sender::RequestToSendCrash(
    const CrashDetails& details) {
  std::string product_name;
  std::unique_ptr<brillo::http::FormData> form_data =
      CreateCrashFormData(details, &product_name);
  if (!form_data) {
    // No form data, retry later
    return CrashRemoveReason::kRetryUploading;
  }

  if (test_mode_) {
    LOG(WARNING) << kTestModeSuccessful;
    return CrashRemoveReason::kFinishedUploading;
  }

  std::string report_id;

  auto stream_data = form_data->ExtractDataStream();
  uint64_t uncompressed_size = stream_data->GetSize();
  // Compress the data before sending it to the server. We compress the entire
  // request body and then specify the Content-Encoding as gzip to achieve this.
  std::vector<unsigned char> compressed_form_data =
      util::GzipStream(std::move(stream_data));

  // Record the send attempt even if it fails. We may still have used up network
  // bandwidth even if we lose the connection at the end.
  const base::FilePath timestamps_dir = paths::Get(paths::kTimestampsDirectory);
  int size = static_cast<int>(compressed_form_data.size());
  if (size == 0) {
    // Compression failed; we'll end up using the uncompressed stream below.
    size = static_cast<int>(uncompressed_size);
  }
  RecordSendAttempt(timestamps_dir, size);

  if (IsMock()) {
    CHECK(!crash_during_testing_) << "crashing as requested";
    // Integration Tests-specific behavior
    if (IsIntegrationTest()) {
      if (!IsMockSuccessful()) {
        LOG(INFO) << "Mocking unsuccessful send";
        return CrashRemoveReason::kRetryUploading;
      }

      LOG(INFO) << "Mocking successful send";
      return CrashRemoveReason::kFinishedUploading;
    }
  } else {
    // Determine the proxy server if it's not given from the options.
    if (proxy_servers_.empty()) {
      EnsureDBusIsReady();
      brillo::http::GetChromeProxyServers(bus_, kReportUploadProdUrl,
                                          &proxy_servers_);
    }
  }

  std::shared_ptr<brillo::http::Transport> transport = GetTransport();

  brillo::ErrorPtr upload_error;
  std::unique_ptr<brillo::http::Response> response;
  if (!compressed_form_data.empty()) {
    response = brillo::http::PostBinaryAndBlock(
        allow_dev_sending_ ? kReportUploadStagingUrl : kReportUploadProdUrl,
        compressed_form_data.data(), compressed_form_data.size(),
        form_data->GetContentType(),
        {{brillo::http::request_header::kContentEncoding, "gzip"}}, transport,
        &upload_error);
  } else {
    LOG(ERROR) << "Failed compressing crash data for upload, perform the "
               << "upload uncompressed";
    // This really should never happen, but it's probably better to try to
    // send this uncompressed even though it requires regenerating all the
    // data since extracting the data stream from the FormData is a
    // potentially destructive operation.
    form_data = CreateCrashFormData(details, &product_name);
    if (!form_data) {
      return CrashRemoveReason::kRetryUploading;
    }
    response = brillo::http::PostFormDataAndBlock(
        allow_dev_sending_ ? kReportUploadStagingUrl : kReportUploadProdUrl,
        std::move(form_data), {} /* headers */, transport, &upload_error);
  }

  if (!response) {
    LOG(ERROR) << "Crash sending failed with error: "
               << upload_error->GetMessage();
    return CrashRemoveReason::kRetryUploading;
  }
  if (!response->IsSuccessful()) {
    int statusCode = response->GetStatusCode();

    if (statusCode == brillo::http::status_code::TooManyRequests) {
      LOG(WARNING) << "Crash being discarded due to throttling, HTTP "
                   << statusCode << ": " << response->GetStatusText();
      return CrashRemoveReason::kTooManyRequests;
    }

    LOG(ERROR) << "Crash sending failed with HTTP " << statusCode << ": "
               << response->GetStatusText();
    return CrashRemoveReason::kRetryUploading;
  }

  report_id = response->ExtractDataAsString();

  if (product_name == "Chrome_ChromeOS")
    product_name = "Chrome";
  if (!util::IsOfficialImage()) {
    base::ReplaceSubstringsAfterOffset(&product_name, 0, "Chrome", "Chromium");
  }
  std::string silent;
  details.metadata.GetString("silent", &silent);
  if (always_write_uploads_log_ || (!USE_CHROMELESS_TTY && silent != "true")) {
    base::FilePath upload_logs_path(paths::Get(paths::kChromeCrashLog));

    // Open the file before we check the normalized path or it will fail if the
    // path doesn't exist.
    base::File upload_logs_file(upload_logs_path, base::File::FLAG_OPEN_ALWAYS |
                                                      base::File::FLAG_APPEND);

    base::FilePath normalized_path;
    if (base::NormalizeFilePath(upload_logs_path, &normalized_path) &&
        upload_logs_path == normalized_path) {
      std::unique_ptr<base::Value> json_entity =
          CreateJsonEntity(report_id, product_name, details);
      std::string upload_log_entry;
      if (!base::JSONWriter::Write(*json_entity, &upload_log_entry)) {
        LOG(WARNING) << "Cannot construct a valid uploads.log entry in JSON "
                        "format, so skip the update.";
        return CrashRemoveReason::kUnparseableMetaFile;
      }

      upload_log_entry += "\n";
      if (!upload_logs_file.IsValid() ||
          upload_logs_file.WriteAtCurrentPos(upload_log_entry.c_str(),
                                             upload_log_entry.size()) !=
              upload_log_entry.size()) {
        PLOG(ERROR) << "Error writing to Chrome uploads.log file";
      }
    } else {
      LOG(ERROR) << "Did not write to Chrome uploads.log file because the "
                 << "normalized path didn't match the target path, target: "
                 << upload_logs_path.value()
                 << " normalized: " << normalized_path.value();
    }
  }
  LOG(INFO) << "Crash report receipt ID " << report_id;
  return CrashRemoveReason::kFinishedUploading;
}

bool Sender::IsNetworkOnline() {
  if (!shill_proxy_) {
    EnsureDBusIsReady();
    shill_proxy_ =
        std::make_unique<org::chromium::flimflam::ManagerProxy>(bus_);
  }
  brillo::VariantDictionary dict;
  brillo::ErrorPtr err;
  if (!shill_proxy_->GetProperties(&dict, &err)) {
    // If we don't know, then just assume we are connected.
    LOG(WARNING) << "Failed making D-Bus call for network state; attempting "
                 << "upload anyways";
    return true;
  }
  const std::string state = brillo::GetVariantValueOrDefault<std::string>(
      dict, shill::kConnectionStateProperty);
  if (state.empty()) {
    // If we didn't get a valid value back, then assume we are connected.
    LOG(WARNING) << "Received empty ConnectionState property from shill; "
                 << "attempting upload anyways";
    return true;
  }
  // Possible values for this are defined in platform2/shill/service.cc, but the
  // only one that means we have an Internet connection is "online". All of the
  // other values represent some other reduced (or no) level of connectivity or
  // the process of establishing a connection.
  return base::EqualsCaseInsensitiveASCII(state, "online");
}

}  // namespace util
