// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/motion_sense_command_lid_angle.h"

#include "base/files/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"

namespace {

constexpr char kIioDevicePath[] =
    "/sys/bus/iio/devices/";
constexpr char kIioNamePath[][48] = {
    "/sys/bus/iio/devices/iio:device0/name",
    "/sys/bus/iio/devices/iio:device1/name",
    "/sys/bus/iio/devices/iio:device2/name",
};
constexpr char kAnglePath[][48] = {
    "/sys/bus/iio/devices/iio:device0/in_angl0_raw",
    "/sys/bus/iio/devices/iio:device1/in_angl0_raw",
    "/sys/bus/iio/devices/iio:device2/in_angl0_raw",
};

}

namespace ec {

MotionSenseCommandLidAngle::MotionSenseCommandLidAngle()
    : MotionSenseCommand(2) {
  SetReq({.cmd = MOTIONSENSE_CMD_LID_ANGLE});
  SetReqSize(sizeof(ec_params_motion_sense::cmd));
  SetRespSize(sizeof(ec_response_motion_sense::lid_angle));
}

uint16_t MotionSenseCommandLidAngle::LidAngle() const {
  static int angle_id = -1;
  const std::string kAngleNameStartings[] = {
      "angl",
  };

  if (!base::PathExists(base::FilePath(kIioDevicePath))) {
    LOG(WARNING) << "LidAngle not initialized yet";
    return 0;
  }

  for (size_t i = 0; i < std::size(kIioNamePath); i++) {
    std::string iio_name;
    base::FilePath path(kIioNamePath[i]);
    ReadFileToString(path, &iio_name);
    base::TrimWhitespaceASCII(iio_name, base::TRIM_TRAILING, &iio_name);

    for (size_t i = 0; i < std::size(kAngleNameStartings); i++) {
      if (base::StartsWith(iio_name, kAngleNameStartings[i])) {
        angle_id = i;
        break;
      }
    }
  }

  uint32_t ret;
  std::string lid_angle;
  base::FilePath path(kAnglePath[angle_id]);
  ReadFileToString(path, &lid_angle);
  base::TrimWhitespaceASCII(lid_angle, base::TRIM_TRAILING, &lid_angle);
  base::StringToUint(lid_angle, &ret);
  return ret;
}

}  // namespace ec
