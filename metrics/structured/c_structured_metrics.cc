// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//
// C wrapper to structured metrics code
//

#include "metrics/structured/c_structured_metrics.h"
#include "metrics/structured/structured_events.h"

namespace bluetooth = metrics::structured::events::bluetooth;

extern "C" void BluetoothAdapterStateChanged(int64_t system_time, int state) {
  bluetooth::BluetoothAdapterStateChanged()
      .SetSystemTime(system_time)
      .SetAdapterState(state)
      .Record();
}

extern "C" void BluetoothPairingStateChanged(int64_t system_time,
                                             const char* device_id,
                                             int device_type,
                                             int state) {
  bluetooth::BluetoothPairingStateChanged()
      .SetSystemTime(system_time)
      .SetDeviceId(device_id)
      .SetDeviceType(device_type)
      .SetPairingState(state)
      .Record();
}

extern "C" void BluetoothAclConnectionStateChanged(int64_t system_time,
                                                   const char* device_id,
                                                   int device_type,
                                                   int connection_direction,
                                                   int state_change_type,
                                                   int state) {
  bluetooth::BluetoothAclConnectionStateChanged()
      .SetSystemTime(system_time)
      .SetDeviceId(device_id)
      .SetDeviceType(device_type)
      .SetConnectionDirection(connection_direction)
      .SetStateChangeType(state_change_type)
      .SetAclConnectionState(state)
      .Record();
}

extern "C" void BluetoothProfileConnectionStateChanged(int64_t system_time,
                                                       const char* device_id,
                                                       int state_change_type,
                                                       int profile,
                                                       int state) {
  bluetooth::BluetoothProfileConnectionStateChanged()
      .SetSystemTime(system_time)
      .SetDeviceId(device_id)
      .SetStateChangeType(state_change_type)
      .SetProfile(profile)
      .SetProfileConnectionState(state)
      .Record();
}

extern "C" void BluetoothDeviceInfoReport(int64_t system_time,
                                          const char* device_id,
                                          int device_type,
                                          int device_class,
                                          int device_category,
                                          int vendor_id,
                                          int vendor_id_source,
                                          int product_id,
                                          int product_version) {
  bluetooth::BluetoothDeviceInfoReport()
      .SetSystemTime(system_time)
      .SetDeviceId(device_id)
      .SetDeviceType(device_type)
      .SetDeviceClass(device_class)
      .SetDeviceCategory(device_category)
      .SetVendorId(vendor_id)
      .SetVendorIdSource(vendor_id_source)
      .SetProductId(product_id)
      .SetProductVersion(product_version)
      .Record();
}
