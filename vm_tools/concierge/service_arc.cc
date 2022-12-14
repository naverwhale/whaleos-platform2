// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/files/file_util.h>
#include <base/logging.h>

#include "vm_tools/common/pstore.h"
#include "vm_tools/concierge/arc_vm.h"
#include "vm_tools/concierge/service.h"
#include "vm_tools/concierge/shared_data.h"
#include "vm_tools/concierge/vm_util.h"

namespace vm_tools {
namespace concierge {

namespace {

// Android data directory.
constexpr char kAndroidDataDir[] = "/run/arcvm/android-data";

// Path to the VM guest kernel.
constexpr char kKernelPath[] = "/opt/google/vms/android/vmlinux";

// Path to the VM rootfs image file.
constexpr char kRootfsPath[] = "/opt/google/vms/android/system.raw.img";

// Path to the VM fstab file.
constexpr char kFstabPath[] = "/run/arcvm/host_generated/fstab";

// Returns true if the path is a valid demo image path.
bool IsValidDemoImagePath(const base::FilePath& path) {
  // A valid demo image path looks like:
  //   /run/imageloader/demo-mode-resources/<version>/android_demo_apps.squash
  std::vector<std::string> components;
  path.GetComponents(&components);
  // TODO(hashimoto): Replace components[4] != ".." with a more strict check.
  // b/219677829
  return components.size() == 6 && components[0] == "/" &&
         components[1] == "run" && components[2] == "imageloader" &&
         components[3] == "demo-mode-resources" && components[4] != ".." &&
         components[5] == "android_demo_apps.squash";
}

// Returns true if the path is a valid data image path.
bool IsValidDataImagePath(const base::FilePath& path) {
  // A valid data image path looks like: /home/root/<hash>/crosvm/YXJjdm0=.img.
  std::vector<std::string> components;
  path.GetComponents(&components);
  return components.size() == 6 && components[0] == "/" &&
         components[1] == "home" && components[2] == "root" &&
         base::ContainsOnlyChars(components[3], "0123456789abcdef") &&
         components[4] == "crosvm" && components[5] == "YXJjdm0=.img";
}

// TODO(hashimoto): Move VM configuration logic from chrome to concierge and
// remove this function. b/219677829
// Returns true if the StartArcVmRequest contains valid ARCVM config values.
bool ValidateStartArcVmRequest(StartArcVmRequest* request) {
  // List of allowed kernel parameters.
  const std::set<std::string> kAllowedKernelParams = {
      "androidboot.arc_generate_pai=1",
      "androidboot.arcvm_mount_debugfs=1",
      "androidboot.container=1",
      "androidboot.disable_download_provider=1",
      "androidboot.disable_media_store_maintenance=1",
      "androidboot.hardware=bertha",
      "androidboot.vshd_service_override=vshd_for_test",
      "init=/init",
      "root=/dev/vda",
      "rw",
  };
  // List of allowed kernel parameter prefixes.
  const std::vector<std::string> kAllowedKernelParamPrefixes = {
      "androidboot.arc_custom_tabs=",
      "androidboot.arc_dalvik_memory_profile=",
      "androidboot.arc_file_picker=",
      "androidboot.arcvm.logd.size=",
      "androidboot.arcvm_metrics_mem_psi_period=",
      "androidboot.arcvm_ureadahead_mode=",
      "androidboot.arcvm_virtio_blk_data=",
      "androidboot.chromeos_channel=",
      "androidboot.dev_mode=",
      "androidboot.disable_runas=",
      "androidboot.disable_system_default_app=",
      "androidboot.enable_notifications_refresh=",
      "androidboot.host_is_in_vm=",
      "androidboot.iioservice_present=",
      "androidboot.keyboard_shortcut_helper_integration=",
      "androidboot.lcd_density=",
      "androidboot.native_bridge=",
      "androidboot.play_store_auto_update=",
      "androidboot.usap_profile=",
      "androidboot.zram_size=",
      // TODO(hashimoto): This param was removed in R98. Remove this.
      "androidboot.image_copy_paste_compat=",
  };
  // Filter kernel params.
  const std::vector<std::string> params(request->params().begin(),
                                        request->params().end());
  request->clear_params();
  for (const auto& param : params) {
    if (kAllowedKernelParams.count(param) != 0) {
      request->add_params(param);
      continue;
    }

    auto it = std::find_if(kAllowedKernelParamPrefixes.begin(),
                           kAllowedKernelParamPrefixes.end(),
                           [&param](const std::string& prefix) {
                             return base::StartsWith(param, prefix);
                           });
    if (it != kAllowedKernelParamPrefixes.end()) {
      request->add_params(param);
      continue;
    }

    LOG(WARNING) << param << " was removed because it doesn't match with any "
                 << "allowed param or prefix";
  }

  // Validate disks.
  constexpr char kEmptyDiskPath[] = "/dev/null";
  if (request->disks().size() < 1 || request->disks().size() > 4) {
    LOG(ERROR) << "Invalid number of disks: " << request->disks().size();
    return false;
  }
  // Disk #0 must be /opt/google/vms/android/vendor.raw.img.
  if (request->disks()[0].path() != "/opt/google/vms/android/vendor.raw.img") {
    LOG(ERROR) << "Disk #0 has invalid path: " << request->disks()[0].path();
    return false;
  }
  // Disk #1 must be a valid demo image path or /dev/null.
  if (request->disks().size() >= 2 &&
      !IsValidDemoImagePath(base::FilePath(request->disks()[1].path())) &&
      request->disks()[1].path() != kEmptyDiskPath) {
    LOG(ERROR) << "Disk #1 has invalid path: " << request->disks()[1].path();
    return false;
  }
  // Disk #2 must be /opt/google/vms/android/apex/payload.img or /dev/null.
  if (request->disks().size() >= 3 &&
      request->disks()[2].path() !=
          "/opt/google/vms/android/apex/payload.img" &&
      request->disks()[2].path() != kEmptyDiskPath) {
    LOG(ERROR) << "Disk #2 has invalid path: " << request->disks()[2].path();
    return false;
  }
  // Disk #3 must be a valid data image path or /dev/null.
  if (request->disks().size() >= 4 &&
      !IsValidDataImagePath(base::FilePath(request->disks()[3].path())) &&
      request->disks()[3].path() != kEmptyDiskPath) {
    LOG(ERROR) << "Disk #3 has invalid path: " << request->disks()[3].path();
    return false;
  }
  return true;
}

}  // namespace

std::unique_ptr<dbus::Response> Service::StartArcVm(
    dbus::MethodCall* method_call) {
  LOG(INFO) << "Received StartArcVm request";
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));
  dbus::MessageReader reader(method_call);
  dbus::MessageWriter writer(dbus_response.get());
  StartArcVmRequest request;
  StartVmResponse response;
  auto helper_result = StartVmHelper<StartArcVmRequest>(
      method_call, &reader, &writer, true /* allow_zero_cpus */);
  if (!helper_result) {
    return dbus_response;
  }
  std::tie(request, response) = *helper_result;

  VmInfo* vm_info = response.mutable_vm_info();
  vm_info->set_vm_type(VmInfo::ARC_VM);

  if (request.disks_size() > kMaxExtraDisks) {
    LOG(ERROR) << "Rejecting request with " << request.disks_size()
               << " extra disks";

    response.set_failure_reason("Too many extra disks");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // TODO(hashimoto): Move VM configuration logic from chrome to concierge and
  // remove this check. b/219677829
  if (!ValidateStartArcVmRequest(&request)) {
    response.set_failure_reason("Invalid request");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  std::vector<Disk> disks;
  // The rootfs can be treated as a disk as well and needs to be added before
  // other disks.
  Disk::Config config{};
  config.o_direct = false;
  config.writable = request.rootfs_writable();
  disks.push_back(Disk(base::FilePath(kRootfsPath), config));
  for (const auto& disk : request.disks()) {
    if (!base::PathExists(base::FilePath(disk.path()))) {
      LOG(ERROR) << "Missing disk path: " << disk.path();
      response.set_failure_reason("One or more disk paths do not exist");
      writer.AppendProtoAsArrayOfBytes(response);
      return dbus_response;
    }
    config.writable = disk.writable();
    disks.push_back(Disk(base::FilePath(disk.path()), config));
  }

  // Create the runtime directory.
  base::FilePath runtime_dir;
  if (!base::CreateTemporaryDirInDir(base::FilePath(kRuntimeDir), "vm.",
                                     &runtime_dir)) {
    PLOG(ERROR) << "Unable to create runtime directory for VM";

    response.set_failure_reason(
        "Internal error: unable to create runtime directory");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Allocate resources for the VM.
  uint32_t vsock_cid = vsock_cid_pool_.Allocate();
  if (vsock_cid == 0) {
    LOG(ERROR) << "Unable to allocate vsock context id";

    response.set_failure_reason("Unable to allocate vsock cid");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }
  vm_info->set_cid(vsock_cid);

  std::unique_ptr<patchpanel::Client> network_client =
      patchpanel::Client::New(bus_);
  if (!network_client) {
    LOG(ERROR) << "Unable to open networking service client";

    response.set_failure_reason("Unable to open network service client");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // Map the chronos user (1000) and the chronos-access group (1001) to the
  // AID_EXTERNAL_STORAGE user and group (1077).
  uint32_t seneschal_server_port = next_seneschal_server_port_++;
  std::unique_ptr<SeneschalServerProxy> server_proxy =
      SeneschalServerProxy::CreateVsockProxy(bus_, seneschal_service_proxy_,
                                             seneschal_server_port, vsock_cid,
                                             {{1000, 1077}}, {{1001, 1077}});
  if (!server_proxy) {
    LOG(ERROR) << "Unable to start shared directory server";

    response.set_failure_reason("Unable to start shared directory server");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  uint32_t seneschal_server_handle = server_proxy->handle();
  vm_info->set_seneschal_server_handle(seneschal_server_handle);

  // Build the plugin params.
  std::vector<std::string> params(
      std::make_move_iterator(request.mutable_params()->begin()),
      std::make_move_iterator(request.mutable_params()->end()));
  params.emplace_back(base::StringPrintf("androidboot.seneschal_server_port=%d",
                                         seneschal_server_port));

  // Start the VM and build the response.
  ArcVmFeatures features;
  features.rootfs_writable = request.rootfs_writable();
  features.use_dev_conf = !request.ignore_dev_conf();

  if (request.has_balloon_policy()) {
    const auto& params = request.balloon_policy();
    features.balloon_policy_params = (LimitCacheBalloonPolicy::Params){
        .reclaim_target_cache = params.reclaim_target_cache(),
        .critical_target_cache = params.critical_target_cache(),
        .moderate_target_cache = params.moderate_target_cache()};
  }

  base::FilePath data_dir = base::FilePath(kAndroidDataDir);
  if (!base::PathExists(data_dir)) {
    LOG(WARNING) << "Android data directory does not exist";

    response.set_failure_reason("Android data directory does not exist");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  VmId vm_id(request.owner_id(), request.name());
  SendVmStartingUpSignal(vm_id, *vm_info);

  const std::vector<uid_t> privileged_quota_uids = {0};  // Root is privileged.
  std::string shared_data = CreateSharedDataParam(data_dir, "_data", true,
                                                  false, privileged_quota_uids);
  std::string shared_data_media = CreateSharedDataParam(
      data_dir, "_data_media", false, true, privileged_quota_uids);

  // TOOD(kansho): |non_rt_cpus_num|, |rt_cpus_num| and |affinity|
  // should be passed from chrome instead of |enable_rt_vcpu|.

  // By default we don't request any RT CPUs
  ArcVmCPUTopology topology(request.cpus(), 0);

  if (request.enable_rt_vcpu()) {
    // We create only 1 RT VCPU for the time being
    topology.SetNumRTCPUs(1);
    topology.CreateCPUAffinity();

    params.emplace_back("isolcpus=" + topology.RTCPUMask());
    params.emplace_back("androidboot.rtcpus=" + topology.RTCPUMask());
    params.emplace_back("androidboot.non_rtcpus=" + topology.NonRTCPUMask());
  }

  VmBuilder vm_builder;
  vm_builder.AppendDisks(std::move(disks))
      .SetCpus(topology.NumCPUs())
      .AppendKernelParam(base::JoinString(params, " "))
      .AppendCustomParam("--android-fstab", kFstabPath)
      .AppendCustomParam("--pstore",
                         base::StringPrintf("path=%s,size=%d", kArcVmPstorePath,
                                            kArcVmPstoreSize))
      .AppendSharedDir(shared_data)
      .AppendSharedDir(shared_data_media)
      .EnableSmt(false /* enable */);

  if (request.enable_rt_vcpu()) {
    vm_builder.AppendCustomParam("--rt-cpus", topology.RTCPUMask());
    if (!topology.AffinityMask().empty())
      vm_builder.AppendCustomParam("--cpu-affinity", topology.AffinityMask());
  }

  if (!topology.CapacityMask().empty()) {
    vm_builder.AppendCustomParam("--cpu-capacity", topology.CapacityMask());
  }

  if (!topology.PackageMask().empty()) {
    for (auto& package : topology.PackageMask()) {
      vm_builder.AppendCustomParam("--cpu-cluster", package);
    }
  }

  if (request.use_hugepages()) {
    vm_builder.AppendCustomParam("--hugepages", "");
  }

  const uint32_t memory_mib = request.memory_mib();
  if (memory_mib > 0) {
    vm_builder.SetMemory(std::to_string(memory_mib));
  } else {
    vm_builder.SetMemory(GetVmMemoryMiB());
  }

  /* Enable THP if the VM has at least 7G of memory */
  if (base::SysInfo::AmountOfPhysicalMemoryMB() >= 7 * 1024) {
    vm_builder.AppendCustomParam("--hugepages", "");
  }

  auto vm =
      ArcVm::Create(base::FilePath(kKernelPath), vsock_cid,
                    std::move(network_client), std::move(server_proxy),
                    std::move(runtime_dir), features, std::move(vm_builder));
  if (!vm) {
    LOG(ERROR) << "Unable to start VM";

    response.set_failure_reason("Unable to start VM");
    writer.AppendProtoAsArrayOfBytes(response);
    return dbus_response;
  }

  // ARCVM is ready.
  LOG(INFO) << "Started VM with pid " << vm->pid();

  response.set_success(true);
  response.set_status(VM_STATUS_RUNNING);
  vm_info->set_ipv4_address(vm->IPv4Address());
  vm_info->set_pid(vm->pid());
  writer.AppendProtoAsArrayOfBytes(response);

  SendVmStartedSignal(vm_id, *vm_info, response.status());

  vms_[vm_id] = std::move(vm);
  return dbus_response;
}

}  // namespace concierge
}  // namespace vm_tools
