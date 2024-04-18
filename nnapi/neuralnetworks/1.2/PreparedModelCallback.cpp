// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is the boilerplate implementation of the IAllocator HAL interface,
// generated by the hidl-gen tool and then modified for use on Chrome OS.
// Modifications include:
// - Removal of non boiler plate client and server related code.
// - Reformatting to meet the Chrome OS coding standards.
//
// Originally generated with the command:
// $ hidl-gen -o output -L c++ -r android.hardware:hardware/interfaces \
//   android.hardware.neuralnetworks@1.2

#define LOG_TAG "android.hardware.neuralnetworks@1.2::PreparedModelCallback"

#include <android/hardware/neuralnetworks/1.2/IPreparedModelCallback.h>
#include <hidl/HidlTransportSupport.h>
#include <hidl/Status.h>

namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_2 {

const char* IPreparedModelCallback::descriptor(
    "android.hardware.neuralnetworks@1.2::IPreparedModelCallback");

::android::hardware::Return<void> IPreparedModelCallback::interfaceChain(
    interfaceChain_cb _hidl_cb) {
  _hidl_cb({
      ::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback::
          descriptor,
      ::android::hardware::neuralnetworks::V1_0::IPreparedModelCallback::
          descriptor,
      ::android::hidl::base::V1_0::IBase::descriptor,
  });
  return ::android::hardware::Void();
}

::android::hardware::Return<void> IPreparedModelCallback::debug(
    const ::android::hardware::hidl_handle& fd,
    const ::android::hardware::hidl_vec<::android::hardware::hidl_string>&
        options) {
  (void)fd;
  (void)options;
  return ::android::hardware::Void();
}

::android::hardware::Return<void> IPreparedModelCallback::interfaceDescriptor(
    interfaceDescriptor_cb _hidl_cb) {
  _hidl_cb(::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback::
               descriptor);
  return ::android::hardware::Void();
}

::android::hardware::Return<void> IPreparedModelCallback::getHashChain(
    getHashChain_cb _hidl_cb) {
  _hidl_cb(
      {/* e1c734d1545e1a4ae749ff1dd9704a8e594c59aea7c8363159dc258e93e0df3b */
       (uint8_t[32]){225, 199, 52,  209, 84,  94,  26,  74,  231, 73,  255,
                     29,  217, 112, 74,  142, 89,  76,  89,  174, 167, 200,
                     54,  49,  89,  220, 37,  142, 147, 224, 223, 59},
       /* 73e03573494ba96f0e711ab7f1956c5b2d54c3da690cd7ecf4d6d0f287447730 */
       (uint8_t[32]){115, 224, 53,  115, 73,  75,  169, 111, 14,  113, 26,
                     183, 241, 149, 108, 91,  45,  84,  195, 218, 105, 12,
                     215, 236, 244, 214, 208, 242, 135, 68,  119, 48},
       /* ec7fd79ed02dfa85bc499426adae3ebe23ef0524f3cd6957139324b83b18ca4c */
       (uint8_t[32]){236, 127, 215, 158, 208, 45,  250, 133, 188, 73,  148,
                     38,  173, 174, 62,  190, 35,  239, 5,   36,  243, 205,
                     105, 87,  19,  147, 36,  184, 59,  24,  202, 76}});
  return ::android::hardware::Void();
}

::android::hardware::Return<void>
IPreparedModelCallback::setHALInstrumentation() {
  return ::android::hardware::Void();
}

::android::hardware::Return<bool> IPreparedModelCallback::linkToDeath(
    const ::android::sp<::android::hardware::hidl_death_recipient>& recipient,
    uint64_t cookie) {
  (void)cookie;
  return (recipient != nullptr);
}

::android::hardware::Return<void> IPreparedModelCallback::ping() {
  return ::android::hardware::Void();
}

::android::hardware::Return<void> IPreparedModelCallback::getDebugInfo(
    getDebugInfo_cb _hidl_cb) {
  ::android::hidl::base::V1_0::DebugInfo info = {};
  info.pid = -1;
  info.ptr = 0;
  info.arch =
#if defined(__LP64__)
      ::android::hidl::base::V1_0::DebugInfo::Architecture::IS_64BIT;
#else
      ::android::hidl::base::V1_0::DebugInfo::Architecture::IS_32BIT;
#endif
  _hidl_cb(info);
  return ::android::hardware::Void();
}

::android::hardware::Return<void>
IPreparedModelCallback::notifySyspropsChanged() {
  ::android::report_sysprop_change();
  return ::android::hardware::Void();
}

::android::hardware::Return<bool> IPreparedModelCallback::unlinkToDeath(
    const ::android::sp<::android::hardware::hidl_death_recipient>& recipient) {
  return (recipient != nullptr);
}

::android::hardware::Return<::android::sp<
    ::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback>>
IPreparedModelCallback::castFrom(
    const ::android::sp<
        ::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback>&
        parent,
    bool /* emitError */) {
  return parent;
}

::android::hardware::Return<::android::sp<
    ::android::hardware::neuralnetworks::V1_2::IPreparedModelCallback>>
IPreparedModelCallback::castFrom(
    const ::android::sp<::android::hidl::base::V1_0::IBase>& parent,
    bool emitError) {
  return ::android::hardware::details::castInterface<
      IPreparedModelCallback, ::android::hidl::base::V1_0::IBase>(
      parent, "android.hardware.neuralnetworks@1.2::IPreparedModelCallback",
      emitError);
}

}  // namespace V1_2
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
