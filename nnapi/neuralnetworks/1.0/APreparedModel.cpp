// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is the boilerplate implementation of the IAllocator HAL interface,
// generated by the hidl-gen tool and then modified for use on Chrome OS.
// Modifications include:
// - Removal of non boiler plate client and server related code.
// - Reformatting to meet the Chrome OS coding standards.
//
// Originally generated with the command:
// $ hidl-gen -o output -L c++-adapter -r android.hardware:hardware/interfaces \
//   android.hardware.neuralnetworks@1.0

#include <android/hardware/neuralnetworks/1.0/APreparedModel.h>
#include <android/hardware/neuralnetworks/1.0/AExecutionCallback.h>
#include <android/hardware/neuralnetworks/1.0/IPreparedModel.h>
#include <hidladapter/HidlBinderAdapter.h>

namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_0 {

APreparedModel::APreparedModel(
    const ::android::sp<
        ::android::hardware::neuralnetworks::V1_0::IPreparedModel>& impl)
    : mImpl(impl) {
}  // Methods from ::android::hardware::neuralnetworks::V1_0::IPreparedModel
   // follow.
::android::hardware::Return<
    ::android::hardware::neuralnetworks::V1_0::ErrorStatus>
APreparedModel::execute(
    const ::android::hardware::neuralnetworks::V1_0::Request& request,
    const ::android::sp<
        ::android::hardware::neuralnetworks::V1_0::IExecutionCallback>&
        callback) {
  auto _hidl_out = mImpl->execute(
      request,
      static_cast<::android::sp<
          ::android::hardware::neuralnetworks::V1_0::IExecutionCallback>>(
          ::android::hardware::neuralnetworks::V1_0::IExecutionCallback::
              castFrom(::android::hardware::details::adaptWithDefault(
                  static_cast<
                      ::android::sp<::android::hardware::neuralnetworks::V1_0::
                                        IExecutionCallback>>(callback),
                  [&] {
                    return new ::android::hardware::neuralnetworks::V1_0::
                        AExecutionCallback(callback);
                  }))));
  if (!_hidl_out.isOkUnchecked()) {
    return _hidl_out;
  }
  return _hidl_out;
}

// Methods from ::android::hidl::base::V1_0::IBase follow.

}  // namespace V1_0
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
