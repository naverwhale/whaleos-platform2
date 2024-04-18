// Copyright (c) 2024 NAVER Corp. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/pinweaver_manager/frontend_whale.h"

#include <fcntl.h>

#include <string>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/scrypt.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/evp.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/backend/pinweaver_manager/persistent_lookup_table.h"
#include "libhwsec/error/pinweaver_error.h"
#include "libhwsec/label_data.pb.h"
#include "libhwsec/status.h"

namespace {

constexpr uint64_t kMaxLabel = 1 << 14;

// Sync with cryptohome/auth_blocks/pin_weaver_auth_block.cc's
constexpr uint32_t kAttemptsLimit = 5;
constexpr uint32_t kInfiniteDelay = std::numeric_limits<uint32_t>::max();

const char kLeCredsDir[] = "/home/.shadow/low_entropy_creds";

constexpr struct {
  uint32_t attempts;
  uint32_t delay;
} kDefaultDelaySchedule[] = {
    {5, kInfiniteDelay},
};

}  // namespace

using ::hwsec_foundation::GetSecureRandom;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;

namespace hwsec {

using CheckCredentialReply = PinWeaverManager::CheckCredentialReply;
using CredentialTreeResult = PinWeaverManagerFrontend::CredentialTreeResult;
using DelaySchedule = PinWeaverManagerFrontend::DelaySchedule;
using ErrorCode = PinWeaverError::PinWeaverErrorCode;
using PinWeaverEccPoint = Backend::PinWeaver::PinWeaverEccPoint;
using StartBiometricsAuthReply = PinWeaverManager::StartBiometricsAuthReply;

PinWeaverManagerFrontendWhale::PinWeaverManagerFrontendWhale(
    MiddlewareDerivative middleware_derivative)
        : FrontendImpl(middleware_derivative),
          plt_(base::FilePath(kLeCredsDir)) {
  plt_.Init();
}

StatusOr<bool> PinWeaverManagerFrontendWhale::IsEnabled() const {
  return true;
}

StatusOr<uint8_t> PinWeaverManagerFrontendWhale::GetVersion() const {
  // It's fake TPM2 based.
  return 2;
}

StatusOr<uint64_t> PinWeaverManagerFrontendWhale::InsertCredential(
    const std::vector<hwsec::OperationPolicySetting>& policies,
    const brillo::SecureBlob& le_secret,
    const brillo::SecureBlob& he_secret,
    const brillo::SecureBlob& reset_secret,
    const DelaySchedule& delay_sched,
    std::optional<uint32_t> expiration_delay) const {
  LOG(INFO) << "PWMFWhale::" <<  __func__;
  std::optional<uint64_t> new_label = GetFreeLabel();
  if (!new_label.has_value()) {
    LOG(ERROR) << "Failed to get free label";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }

  // Encrypt le_secret and he_secret.
  brillo::SecureBlob salt(
      PKCS5_SALT_LEN, new_label.value() % std::numeric_limits<uint8_t>::max());
  brillo::SecureBlob aes_key(hwsec_foundation::kDefaultAesKeySize);
  if (!hwsec_foundation::PasskeyToAesKey(
        le_secret, salt, hwsec_foundation::kDefaultPasswordRounds, &aes_key,
        /* iv */ nullptr)) {
    LOG(ERROR) << "Failed to encrypt secrets";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }
  const auto le_iv = hwsec_foundation::CreateSecureRandomBlob(
      hwsec_foundation::kAesBlockSize);
  brillo::Blob encrypted_le_secret;
  if (!hwsec_foundation::AesEncryptDeprecated(
        le_secret, aes_key,
        brillo::Blob(le_iv.begin(), le_iv.end()), &encrypted_le_secret)) {
    LOG(ERROR) << "Failed to wrap le secret.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }
  const auto he_iv = hwsec_foundation::CreateSecureRandomBlob(
      hwsec_foundation::kAesBlockSize);
  brillo::Blob encrypted_he_secret;
  if (!hwsec_foundation::AesEncryptDeprecated(
        he_secret, aes_key,
        brillo::Blob(he_iv.begin(), he_iv.end()), &encrypted_he_secret)) {
    LOG(ERROR) << "Failed to wrap he secret.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }

  LabelData new_data;
  new_data.set_le_secret(brillo::BlobToString(encrypted_le_secret));
  new_data.set_le_iv(le_iv.to_string());
  new_data.set_he_secret(brillo::BlobToString(encrypted_he_secret));
  new_data.set_he_iv(he_iv.to_string());
  new_data.set_reset_secret(reset_secret.to_string());
  new_data.set_attempts(0);
  if (!StoreToStorage(new_label.value(), new_data)) {
    LOG(ERROR) << "Failed to store secrets.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }

  return new_label.value();
}

StatusOr<CheckCredentialReply>
PinWeaverManagerFrontendWhale::CheckCredential(
    uint64_t label,
    const brillo::SecureBlob& le_secret) const {
  LOG(INFO) <<  "PWMFWhale::" << __func__;
  std::vector<uint8_t> merged_blob;
  PLTError ret_val = plt_.GetValue(label, merged_blob);
  if (ret_val == PLT_KEY_NOT_FOUND) {
    LOG(ERROR) << "Not found key: " << label << " in PLT.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }
  if (ret_val != PLT_SUCCESS) {
    LOG(ERROR) << "Couldn't get key: " << label << " in PLT.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }

  LabelData data;
  if (!data.ParseFromArray(merged_blob.data(), merged_blob.size())) {
    LOG(ERROR) << "Couldn't deserialize data for label " << label;
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }

  // Decrypt le_secret.
  brillo::SecureBlob salt(PKCS5_SALT_LEN,
                          label % std::numeric_limits<uint8_t>::max());
  brillo::SecureBlob aes_key(hwsec_foundation::kDefaultAesKeySize);
  if (!hwsec_foundation::PasskeyToAesKey(
        le_secret, salt, hwsec_foundation::kDefaultPasswordRounds, &aes_key,
        /* iv */ nullptr)) {
    LOG(ERROR) << "Failed to get aes key.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }
  brillo::Blob le_secret_saved(data.le_secret().begin(),
                               data.le_secret().end());
  brillo::Blob le_iv(data.le_iv().begin(),
                     data.le_iv().end());
  brillo::SecureBlob decrypted_le_secret;
  if (!hwsec_foundation::AesDecryptDeprecated(le_secret_saved, aes_key, le_iv,
                                              &decrypted_le_secret)) {
    LOG(ERROR) << "Failed to unwrap le secret.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }

  if (le_secret != decrypted_le_secret) {
    LOG(ERROR) << " Incorrect le secret.";
    // Increase wrong attempts.
    if (RemoveCredential(label).ok()) {
      LOG(ERROR) << " Increase wrong attempts "
          << " current attempts: " << data.attempts();
      data.set_attempts(data.attempts() + 1);
      StoreToStorage(label, data);
    }
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kInvalidLeSecret);
    return status;
  }

  // Decrypt he_secret.
  brillo::Blob he_secret_saved(data.he_secret().begin(),
                               data.he_secret().end());
  brillo::Blob he_iv(data.he_iv().begin(),
                     data.he_iv().end());
  brillo::SecureBlob decrypted_he_secret;
  if (!hwsec_foundation::AesDecryptDeprecated(he_secret_saved, aes_key, he_iv,
                                            &decrypted_he_secret)) {
    LOG(ERROR) << "Failed to unwrap he secret.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }

  brillo::SecureBlob reset_secret(data.reset_secret().begin(),
                                  data.reset_secret().end());

  return CheckCredentialReply{
      .he_secret = decrypted_he_secret,
      .reset_secret = reset_secret,
  };
}

Status PinWeaverManagerFrontendWhale::RemoveCredential(
    const uint64_t label) const {
  LOG(INFO) <<  "PWMFWhale::" << __func__;
  if (plt_.RemoveKey(label) != PLT_SUCCESS) {
    LOG(ERROR) << "Couldn't remove label: " << label << " in PLT.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }

  return OkStatus();
}

Status PinWeaverManagerFrontendWhale::ResetCredential(
    uint64_t label,
    const brillo::SecureBlob& reset_secret,
    ResetType reset_type /* unused */) const {
  LOG(INFO) <<  "PWMFWhale::" << __func__;
  std::vector<uint8_t> merged_blob;
  PLTError ret_val = plt_.GetValue(label, merged_blob);
  if (ret_val == PLT_KEY_NOT_FOUND) {
    LOG(ERROR) << "Not found key: " << label << " in PLT.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }
  if (ret_val != PLT_SUCCESS) {
    LOG(ERROR) << "Couldn't get key: " << label << " in PLT.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }
  LabelData data;
  if (!data.ParseFromArray(merged_blob.data(), merged_blob.size())) {
    LOG(ERROR) << "Couldn't deserialize data for label " << label;
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }
  brillo::SecureBlob reset_secret_saved(data.reset_secret().begin(),
                                        data.reset_secret().end());
  if (reset_secret != reset_secret_saved) {
    LOG(ERROR) << " Incorrect reset secret.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kInvalidResetSecret);
    return status;
  }
  return OkStatus();
}

StatusOr<uint32_t> PinWeaverManagerFrontendWhale::GetWrongAuthAttempts(
    const uint64_t label) const {
  LOG(INFO) <<  "PWMFWhale::" << __func__;
  std::vector<uint8_t> merged_blob;
  PLTError ret_val = plt_.GetValue(label, merged_blob);
  if (ret_val == PLT_KEY_NOT_FOUND) {
    LOG(ERROR) << "Not found key: " << label << " in PLT.";
    return 0;
  }
  if (ret_val != PLT_SUCCESS) {
    LOG(ERROR) << "Couldn't get key: " << label << " in PLT.";
    return 0;
  }

  LabelData data;
  if (!data.ParseFromArray(merged_blob.data(), merged_blob.size())) {
    LOG(ERROR) << "Couldn't deserialize data for label " << label;
    return 0;
  }

  return data.attempts();
}

StatusOr<DelaySchedule> PinWeaverManagerFrontendWhale::GetDelaySchedule(
    const uint64_t label) const {
  std::map<uint32_t, uint32_t> delay_sched;
  for (const auto& entry : kDefaultDelaySchedule) {
    delay_sched[entry.attempts] = entry.delay;
  }

  hwsec::StatusOr<DelaySchedule> result = delay_sched;
  if (!result.ok()) {
    LOG(INFO) <<  "PWMFWhale::" << __func__ << " not reached.";
    Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
    return status;
  }

  return result.value();
}


StatusOr<uint32_t> PinWeaverManagerFrontendWhale::GetDelayInSeconds(
    const uint64_t label) const {
  ASSIGN_OR_RETURN(uint64_t wrong_attempts, GetWrongAuthAttempts(label));
  if (wrong_attempts > kAttemptsLimit) {
    return kInfiniteDelay;
  }

  return 0;
}

StatusOr<std::optional<uint32_t>>
PinWeaverManagerFrontendWhale::GetExpirationInSeconds(
    const uint64_t label) const {
  LOG(ERROR) << "PWMFWhale::" <<  __func__ << " not supported.";
  return std::nullopt;
}

StatusOr<PinWeaverEccPoint> PinWeaverManagerFrontendWhale::GeneratePk(
    uint8_t auth_channel, const PinWeaverEccPoint& client_public_key) const {
  // Something biometrics.
  LOG(ERROR) << "PWMFWhale::" <<  __func__ << " not supported.";
  Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
  return status;
}

StatusOr<uint64_t> PinWeaverManagerFrontendWhale::InsertRateLimiter(
    uint8_t auth_channel,
    const std::vector<hwsec::OperationPolicySetting>& policies,
    const brillo::SecureBlob& reset_secret,
    const DelaySchedule& delay_sched,
    std::optional<uint32_t> expiration_delay) const {
  LOG(ERROR) << "PWMFWhale::" <<  __func__ << " not supported.";
  Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
  return status;
}

StatusOr<StartBiometricsAuthReply>
PinWeaverManagerFrontendWhale::StartBiometricsAuth(
    uint8_t auth_channel,
    uint64_t label,
    const brillo::Blob& client_nonce) const {
  // Something biometrics.
  LOG(ERROR) << "PWMFWhale::" <<  __func__ << " not supported.";
  Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
  return status;
}

Status PinWeaverManagerFrontendWhale::BlockGeneratePk() const {
  // Something biometrics.
  LOG(ERROR) << "PWMFWhale::" <<  __func__ << " not supported.";
  Status status = MakeStatus<PinWeaverError>(ErrorCode::kOther);
  return status;
}

std::optional<uint64_t> PinWeaverManagerFrontendWhale::GetFreeLabel() const {
  std::vector<uint64_t> used_keys;
  plt_.GetUsedKeys(used_keys);
  uint64_t num_free_keys = kMaxLabel - used_keys.size();
  if (num_free_keys <= 0) {
    // No more labels.
    return std::nullopt;
  }

  uint64_t new_label;
  GetSecureRandom(reinterpret_cast<unsigned char*>(&new_label),
                  sizeof(new_label));
  new_label %= num_free_keys;
  std::sort(used_keys.begin(), used_keys.end());
  for (uint64_t used_key : used_keys) {
    if (used_key > new_label) {
      break;
    }
    new_label++;
  }
  CHECK_LT(new_label, kMaxLabel);
  CHECK(!plt_.KeyExists(new_label));

  return new_label;
}

bool PinWeaverManagerFrontendWhale::StoreToStorage(
    uint64_t label, LabelData& label_data) const {
  std::vector<uint8_t> merged_blob(label_data.ByteSizeLong());
  if (!label_data.SerializeToArray(merged_blob.data(), merged_blob.size())) {
    LOG(ERROR) << "Couldn't serialize leaf data, label: " << label;
    return false;
  }
  if (plt_.StoreValue(label, merged_blob) != PLT_SUCCESS) {
    LOG(ERROR) << "Couldn't store label: " << label << " in PLT.";
    return false;
  }

  return true;
}

}  // namespace hwsec
