// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/bind.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <dbus/bus.h>
#include <dbus/object_path.h>
#include <dbus/message.h>
#include <chromeos/dbus/service_constants.h>

#include "missive/dbus/upload_client.h"
#include "missive/proto/interface.pb.h"
#include "missive/proto/record.pb.h"
#include "missive/util/status.h"
#include "missive/util/statusor.h"

namespace reporting {

UploadClient::UploadClient(scoped_refptr<dbus::Bus> bus,
                           dbus::ObjectProxy* chrome_proxy)
    : bus_(bus), chrome_proxy_(chrome_proxy) {}
UploadClient::~UploadClient() = default;

// static
scoped_refptr<UploadClient> UploadClient::Create() {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;

  // Despite being a base::RefCountedThreadSafe object, dbus::Bus doesn't follow
  // the normal pattern of creation. The constructor is public and this is the
  // standard usage.
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));
  CHECK(bus->Connect());
  CHECK(bus->SetUpAsyncOperations());
  dbus::ObjectProxy* chrome_proxy = bus->GetObjectProxy(
      chromeos::kChromeReportingServiceName,
      dbus::ObjectPath(chromeos::kChromeReportingServicePath));
  CHECK(chrome_proxy);

  return Create(bus, chrome_proxy);
}

// static
scoped_refptr<UploadClient> UploadClient::Create(
    scoped_refptr<dbus::Bus> bus, dbus::ObjectProxy* chrome_proxy) {
  return base::WrapRefCounted(new UploadClient(bus, chrome_proxy));
}

void UploadClient::SendEncryptedRecords(
    std::unique_ptr<std::vector<EncryptedRecord>> records,
    const bool need_encryption_keys,
    HandleUploadResponseCallback response_callback) {
  // Build the request.
  UploadEncryptedRecordRequest request;
  for (const auto& record : *records) {
    request.add_encrypted_record()->CheckTypeAndMergeFrom(record);
  }
  request.set_need_encryption_keys(need_encryption_keys);

  // Make the call to Chrome
  auto call = std::make_unique<dbus::MethodCall>(
      chromeos::kChromeReportingServiceInterface,
      chromeos::kChromeReportingServiceUploadEncryptedRecordMethod);
  dbus::MethodCall* const raw_call = call.get();
  {
    dbus::MessageWriter writer(raw_call);
    if (!writer.AppendProtoAsArrayOfBytes(request)) {
      Status status(error::UNKNOWN,
                    "MessageWriter was unable to append the request.");
      LOG(ERROR) << status;
      std::move(response_callback).Run(status);
      return;
    }
  }
  bus_->GetOriginTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &dbus::ObjectProxy::CallMethod, base::Unretained(chrome_proxy_),
          raw_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
          base::BindOnce(&UploadClient::HandleUploadEncryptedRecordResponse,
                         this, std::move(call), std::move(response_callback))));
}

void UploadClient::HandleUploadEncryptedRecordResponse(
    const std::unique_ptr<dbus::MethodCall> call,  // owned thru response.
    HandleUploadResponseCallback response_callback,
    dbus::Response* response) const {
  if (!response) {
    std::move(response_callback)
        .Run(Status(error::UNAVAILABLE,
                    "Chrome is not responding, upload skipped."));
    return;
  }

  dbus::MessageReader reader(response);
  UploadEncryptedRecordResponse response_proto;
  if (!reader.PopArrayOfBytesAsProto(&response_proto)) {
    std::move(response_callback)
        .Run(Status(error::INTERNAL, "Response was not parseable."));
    return;
  }

  std::move(response_callback).Run(std::move(response_proto));
}

}  // namespace reporting
