/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <hardware/camera3.h>

#include "camera/mojo/camera3.mojom.h"
#include "camera/mojo/camera_common.mojom.h"
#include "cros-camera/camera_buffer_manager.h"

namespace cros {

namespace {

#define CHECK_MOJOM_DEFINITION(name, enum_class)                         \
  static_assert(name == static_cast<int>(cros::mojom::enum_class::name), \
                "Definition of " #name                                   \
                " is inconsistent between mojom and Android framework");

// We must make sure the HAL pixel format definitions in mojom and from Android
// framework are consistent.
#define CHECK_FORMAT_DEFINITION(format) \
  CHECK_MOJOM_DEFINITION(format, HalPixelFormat)

CHECK_FORMAT_DEFINITION(HAL_PIXEL_FORMAT_RGBA_8888);
CHECK_FORMAT_DEFINITION(HAL_PIXEL_FORMAT_RGBX_8888);
CHECK_FORMAT_DEFINITION(HAL_PIXEL_FORMAT_BGRA_8888);
CHECK_FORMAT_DEFINITION(HAL_PIXEL_FORMAT_YCrCb_420_SP);
CHECK_FORMAT_DEFINITION(HAL_PIXEL_FORMAT_YCbCr_422_I);
CHECK_FORMAT_DEFINITION(HAL_PIXEL_FORMAT_BLOB);
CHECK_FORMAT_DEFINITION(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);
CHECK_FORMAT_DEFINITION(HAL_PIXEL_FORMAT_YCbCr_420_888);
CHECK_FORMAT_DEFINITION(HAL_PIXEL_FORMAT_YV12);

#define CHECK_CAMERA_FACING_DEFINITION(facing) \
  CHECK_MOJOM_DEFINITION(facing, CameraFacing)

CHECK_CAMERA_FACING_DEFINITION(CAMERA_FACING_BACK);
CHECK_CAMERA_FACING_DEFINITION(CAMERA_FACING_FRONT);
CHECK_CAMERA_FACING_DEFINITION(CAMERA_FACING_EXTERNAL);

#define CHECK_STREAM_TYPE_DEFINITION(type) \
  CHECK_MOJOM_DEFINITION(type, Camera3StreamType)

CHECK_STREAM_TYPE_DEFINITION(CAMERA3_STREAM_OUTPUT);
CHECK_STREAM_TYPE_DEFINITION(CAMERA3_STREAM_INPUT);
CHECK_STREAM_TYPE_DEFINITION(CAMERA3_STREAM_BIDIRECTIONAL);

#define CHECK_STREAM_ROTATION_DEFINITION(rotation) \
  CHECK_MOJOM_DEFINITION(rotation, Camera3StreamRotation)

CHECK_STREAM_ROTATION_DEFINITION(CAMERA3_STREAM_ROTATION_0);
CHECK_STREAM_ROTATION_DEFINITION(CAMERA3_STREAM_ROTATION_90);
CHECK_STREAM_ROTATION_DEFINITION(CAMERA3_STREAM_ROTATION_180);
CHECK_STREAM_ROTATION_DEFINITION(CAMERA3_STREAM_ROTATION_270);

#define CHECK_STREAM_CONFIGURATION_MODE_DEFINITION(mode) \
  CHECK_MOJOM_DEFINITION(mode, Camera3StreamConfigurationMode)

CHECK_STREAM_CONFIGURATION_MODE_DEFINITION(
    CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE);
CHECK_STREAM_CONFIGURATION_MODE_DEFINITION(
    CAMERA3_STREAM_CONFIGURATION_CONSTRAINED_HIGH_SPEED_MODE);

#define CHECK_REQUEST_TEMPLATE_DEFINITION(temp) \
  CHECK_MOJOM_DEFINITION(temp, Camera3RequestTemplate)

CHECK_REQUEST_TEMPLATE_DEFINITION(CAMERA3_TEMPLATE_PREVIEW);
CHECK_REQUEST_TEMPLATE_DEFINITION(CAMERA3_TEMPLATE_STILL_CAPTURE);
CHECK_REQUEST_TEMPLATE_DEFINITION(CAMERA3_TEMPLATE_VIDEO_RECORD);
CHECK_REQUEST_TEMPLATE_DEFINITION(CAMERA3_TEMPLATE_VIDEO_SNAPSHOT);
CHECK_REQUEST_TEMPLATE_DEFINITION(CAMERA3_TEMPLATE_ZERO_SHUTTER_LAG);
CHECK_REQUEST_TEMPLATE_DEFINITION(CAMERA3_TEMPLATE_MANUAL);
CHECK_REQUEST_TEMPLATE_DEFINITION(CAMERA3_TEMPLATE_COUNT);

#define CHECK_BUFFER_STATUS_DEFINITION(status) \
  CHECK_MOJOM_DEFINITION(status, Camera3BufferStatus)

CHECK_BUFFER_STATUS_DEFINITION(CAMERA3_BUFFER_STATUS_OK);
CHECK_BUFFER_STATUS_DEFINITION(CAMERA3_BUFFER_STATUS_ERROR);

#define CHECK_MSG_TYPE_DEFINITION(type) \
  CHECK_MOJOM_DEFINITION(type, Camera3MsgType)

CHECK_MSG_TYPE_DEFINITION(CAMERA3_MSG_ERROR);
CHECK_MSG_TYPE_DEFINITION(CAMERA3_MSG_SHUTTER);

#define CHECK_ERROR_MSG_CODE_DEFINITION(code) \
  CHECK_MOJOM_DEFINITION(code, Camera3ErrorMsgCode)

CHECK_ERROR_MSG_CODE_DEFINITION(CAMERA3_MSG_ERROR_DEVICE);
CHECK_ERROR_MSG_CODE_DEFINITION(CAMERA3_MSG_ERROR_REQUEST);
CHECK_ERROR_MSG_CODE_DEFINITION(CAMERA3_MSG_ERROR_RESULT);
CHECK_ERROR_MSG_CODE_DEFINITION(CAMERA3_MSG_ERROR_BUFFER);

#define CHECK_DEVICE_STATUS_DEFINITION(status) \
  CHECK_MOJOM_DEFINITION(status, CameraDeviceStatus)

CHECK_DEVICE_STATUS_DEFINITION(CAMERA_DEVICE_STATUS_NOT_PRESENT);
CHECK_DEVICE_STATUS_DEFINITION(CAMERA_DEVICE_STATUS_PRESENT);
CHECK_DEVICE_STATUS_DEFINITION(CAMERA_DEVICE_STATUS_ENUMERATING);

#define CHECK_TORCH_MODE_STATUS_DEFINITION(status) \
  CHECK_MOJOM_DEFINITION(status, TorchModeStatus)

CHECK_TORCH_MODE_STATUS_DEFINITION(TORCH_MODE_STATUS_NOT_AVAILABLE);
CHECK_TORCH_MODE_STATUS_DEFINITION(TORCH_MODE_STATUS_AVAILABLE_OFF);
CHECK_TORCH_MODE_STATUS_DEFINITION(TORCH_MODE_STATUS_AVAILABLE_ON);

}  // namespace

}  // namespace cros
