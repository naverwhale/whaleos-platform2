// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_STORAGE_STORAGE_CONFIGURATION_H_
#define MISSIVE_STORAGE_STORAGE_CONFIGURATION_H_

#include <string>

#include <base/files/file_path.h>
#include <base/strings/string_piece.h>
#include <base/time/time.h>

namespace reporting {

// Storage options class allowing to set parameters individually, e.g.:
// Storage::Create(Options()
//                     .set_directory("/var/cache/reporting")
//                     .set_max_record_size(4 * 1024u)
//                     .set_max_total_files_size(64 * 1024u * 1024u)
//                     .set_max_total_memory_size(256 * 1024u),
//                 callback);
class StorageOptions {
 public:
  StorageOptions();
  StorageOptions(const StorageOptions& options);
  StorageOptions& operator=(const StorageOptions& options);
  ~StorageOptions();
  StorageOptions& set_directory(const base::FilePath& directory) {
    directory_ = directory;
    return *this;
  }
  StorageOptions& set_signature_verification_public_key(
      base::StringPiece signature_verification_public_key) {
    signature_verification_public_key_ =
        std::string(signature_verification_public_key);
    return *this;
  }
  StorageOptions& set_max_record_size(size_t max_record_size) {
    max_record_size_ = max_record_size;
    return *this;
  }
  StorageOptions& set_max_total_files_size(uint64_t max_total_files_size) {
    max_total_files_size_ = max_total_files_size;
    return *this;
  }
  StorageOptions& set_max_total_memory_size(uint64_t max_total_memory_size) {
    max_total_memory_size_ = max_total_memory_size;
    return *this;
  }
  StorageOptions& set_single_file_size(uint64_t single_file_size) {
    single_file_size_ = single_file_size;
    return *this;
  }
  const base::FilePath& directory() const { return directory_; }
  base::StringPiece signature_verification_public_key() const {
    return signature_verification_public_key_;
  }
  size_t max_record_size() const { return max_record_size_; }
  uint64_t max_total_files_size() const { return max_total_files_size_; }
  uint64_t max_total_memory_size() const { return max_total_memory_size_; }
  uint64_t single_file_size() const { return single_file_size_; }

 private:
  // Subdirectory of the location assigned for this Storage.
  base::FilePath directory_;

  // Public key for signature verification when encryption key
  // is delivered to Storage.
  std::string signature_verification_public_key_;

  // Maximum record size.
  size_t max_record_size_ = 1 * 1024LL * 1024LL;  // 1 MiB

  // Maximum total size of all files in all queues.
  uint64_t max_total_files_size_ = 64 * 1024LL * 1024LL;  // 64 MiB

  // Maximum memory usage (reading buffers).
  uint64_t max_total_memory_size_ = 4 * 1024LL * 1024LL;  // 4 MiB

  // Cut-off size of an individual file in all queues.
  // When file exceeds this size, the new file is created
  // for further records. Note that each file must have at least
  // one record before it is closed, regardless of that record size.
  uint64_t single_file_size_ = 1 * 1024LL * 1024LL;  // 1 MiB
};

// Single queue options class allowing to set parameters individually, e.g.:
// StorageQueue::Create(QueueOptions(storage_options)
//                  .set_subdirectory("reporting")
//                  .set_file_prefix("p00000001"),
//                 callback);
// storage_options must outlive QueueOptions.
class QueueOptions {
 public:
  explicit QueueOptions(const StorageOptions& storage_options)
      : storage_options_(storage_options) {}
  QueueOptions(const QueueOptions& options) = default;
  //   QueueOptions& operator=(const QueueOptions& options) = default;
  QueueOptions& set_subdirectory(const std::string& subdirectory) {
    directory_ = storage_options_.directory().Append(subdirectory);
    return *this;
  }
  QueueOptions& set_file_prefix(const std::string& file_prefix) {
    file_prefix_ = file_prefix;
    return *this;
  }
  QueueOptions& set_upload_period(base::TimeDelta upload_period) {
    upload_period_ = upload_period;
    return *this;
  }
  QueueOptions& set_upload_retry_delay(base::TimeDelta upload_retry_delay) {
    upload_retry_delay_ = upload_retry_delay;
    return *this;
  }
  const base::FilePath& directory() const { return directory_; }
  const std::string& file_prefix() const { return file_prefix_; }
  size_t max_record_size() const { return storage_options_.max_record_size(); }
  size_t max_total_files_size() const {
    return storage_options_.max_total_files_size();
  }
  size_t max_total_memory_size() const {
    return storage_options_.max_total_memory_size();
  }
  uint64_t single_file_size() const {
    return storage_options_.single_file_size();
  }
  base::TimeDelta upload_period() const { return upload_period_; }
  base::TimeDelta upload_retry_delay() const { return upload_retry_delay_; }

 private:
  // Whole storage options, which this queue options are based on.
  const StorageOptions& storage_options_;

  // Subdirectory of the Storage location assigned for this StorageQueue.
  base::FilePath directory_;
  // Prefix of data files assigned for this StorageQueue.
  std::string file_prefix_;
  // Time period the data is uploaded with.
  // If 0, uploaded immediately after a new record is stored
  // (this setting is intended for the immediate priority).
  // Can be set to infinity - in that case Flush() is expected to be
  // called from time to time.
  base::TimeDelta upload_period_;
  // Retry delay for a failed upload. If 0, not retried at all
  // (should only be set to 0 in periodic queues).
  base::TimeDelta upload_retry_delay_;
};

}  // namespace reporting

#endif  // MISSIVE_STORAGE_STORAGE_CONFIGURATION_H_
