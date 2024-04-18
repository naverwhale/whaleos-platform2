// Copyright (c) 2024 NAVER Corp. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_PINWEAVER_MANAGER_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_PINWEAVER_MANAGER_FRONTEND_IMPL_H_

#include <cstdint>
#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/pinweaver_manager/persistent_lookup_table.h"
#include "libhwsec/frontend/frontend_impl.h"
#include "libhwsec/frontend/pinweaver_manager/frontend.h"
#include "libhwsec/label_data.pb.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class PinWeaverManagerFrontendWhale : public PinWeaverManagerFrontend,
                                      public FrontendImpl {
 public:
  explicit PinWeaverManagerFrontendWhale(
      MiddlewareDerivative middleware_derivative);
  ~PinWeaverManagerFrontendWhale() override = default;

  StatusOr<bool> IsEnabled() const override;
  StatusOr<uint8_t> GetVersion() const override;
  StatusOr<uint64_t> InsertCredential(
      const std::vector<OperationPolicySetting>& policies,
      const brillo::SecureBlob& le_secret,
      const brillo::SecureBlob& he_secret,
      const brillo::SecureBlob& reset_secret,
      const DelaySchedule& delay_schedule,
      std::optional<uint32_t> expiration_delay) const override;
  StatusOr<CheckCredentialReply> CheckCredential(
      const uint64_t label, const brillo::SecureBlob& le_secret) const override;
  Status RemoveCredential(const uint64_t label) const override;
  Status ResetCredential(const uint64_t label,
                         const brillo::SecureBlob& reset_secret,
                         ResetType reset_type) const override;
  StatusOr<uint32_t> GetWrongAuthAttempts(const uint64_t label) const override;
  StatusOr<DelaySchedule> GetDelaySchedule(const uint64_t label) const override;
  StatusOr<uint32_t> GetDelayInSeconds(const uint64_t label) const override;
  StatusOr<std::optional<uint32_t>> GetExpirationInSeconds(
      const uint64_t label) const override;
  StatusOr<PinWeaverEccPoint> GeneratePk(
      uint8_t auth_channel,
      const PinWeaverEccPoint& client_public_key) const override;
  StatusOr<uint64_t> InsertRateLimiter(
      uint8_t auth_channel,
      const std::vector<OperationPolicySetting>& policies,
      const brillo::SecureBlob& reset_secret,
      const DelaySchedule& delay_schedule,
      std::optional<uint32_t> expiration_delay) const override;
  StatusOr<StartBiometricsAuthReply> StartBiometricsAuth(
      uint8_t auth_channel,
      const uint64_t label,
      const brillo::Blob& client_nonce) const override;
  Status BlockGeneratePk() const override;

 private:
  std::optional<uint64_t> GetFreeLabel() const;
  bool StoreToStorage(uint64_t label, LabelData& label_data) const;

  // This is used to actually store and retrieve data from the backing disk
  // storage.
  // Hack for const method.
  mutable PersistentLookupTable plt_;

};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_PINWEAVER_MANAGER_FRONTEND_IMPL_H_
