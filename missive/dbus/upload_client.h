// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_DBUS_UPLOAD_CLIENT_H_
#define MISSIVE_DBUS_UPLOAD_CLIENT_H_

#include <atomic>
#include <memory>
#include <vector>

#include <base/callback.h>
#include <base/memory/ref_counted.h>
#include <base/memory/scoped_refptr.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>

#include "missive/proto/interface.pb.h"
#include "missive/proto/record.pb.h"
#include "missive/util/statusor.h"

namespace reporting {

class UploadClient : public base::RefCountedThreadSafe<UploadClient> {
 public:
  // The requestor will receive a response to their UploadEncryptedRequest via
  // the HandleUploadResponseCallback.
  using HandleUploadResponseCallback =
      base::OnceCallback<void(StatusOr<UploadEncryptedRecordResponse>)>;

  // Factory method for creating a UploadClient.
  static scoped_refptr<UploadClient> Create();

  // Utilizes DBus to send a list of encrypted records to Chrome. Caller can
  // expect a response via the |response_callback|.
  virtual void SendEncryptedRecords(
      std::unique_ptr<std::vector<EncryptedRecord>> records,
      bool need_encryption_keys,
      HandleUploadResponseCallback response_callback);

 protected:
  // Factory method for creating a UploadClient with specified |bus| and
  // |chrome_proxy|.
  static scoped_refptr<UploadClient> Create(scoped_refptr<dbus::Bus> bus,
                                            dbus::ObjectProxy* chrome_proxy);

  UploadClient(scoped_refptr<dbus::Bus> bus, dbus::ObjectProxy* chrome_proxy);
  virtual ~UploadClient();

  void HandleUploadEncryptedRecordResponse(
      const std::unique_ptr<dbus::MethodCall> call,  // owned thru response.
      HandleUploadResponseCallback response_callback,
      dbus::Response* response) const;

 private:
  friend base::RefCountedThreadSafe<UploadClient>;

  scoped_refptr<dbus::Bus> const bus_;
  dbus::ObjectProxy* const chrome_proxy_;
};

}  // namespace reporting

#endif  // MISSIVE_DBUS_UPLOAD_CLIENT_H_
