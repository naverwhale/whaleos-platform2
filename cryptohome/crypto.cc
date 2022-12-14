// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Contains the implementation of class Crypto

#include "cryptohome/crypto.h"

#include <sys/types.h>
#include <unistd.h>

#include <limits>
#include <map>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>
#include <crypto/sha2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "cryptohome/attestation.pb.h"
#include "cryptohome/crypto/aes.h"
#include "cryptohome/crypto/hmac.h"
#include "cryptohome/crypto/scrypt.h"
#include "cryptohome/crypto/secure_blob_util.h"
#include "cryptohome/cryptohome_common.h"
#include "cryptohome/cryptohome_keys_manager.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/le_credential_manager_impl.h"
#include "cryptohome/libscrypt_compat.h"
#include "cryptohome/platform.h"
#include "cryptohome/vault_keyset.h"

using base::FilePath;
using brillo::SecureBlob;
using hwsec::error::TPMErrorBase;

namespace cryptohome {

namespace {

// Location where we store the Low Entropy (LE) credential manager related
// state.
const char kSignInHashTreeDir[] = "/home/.shadow/low_entropy_creds";

// Maximum size of the salt file.
const int64_t kSystemSaltMaxSize = (1 << 20);  // 1 MB

// File permissions of salt file (modulo umask).
const mode_t kSaltFilePermissions = 0644;

}  // namespace

Crypto::Crypto(Platform* platform)
    : tpm_(NULL),
      platform_(platform),
      cryptohome_keys_manager_(NULL),
      disable_logging_for_tests_(false) {}

Crypto::~Crypto() {}

bool Crypto::Init(Tpm* tpm, CryptohomeKeysManager* cryptohome_keys_manager) {
  CHECK(cryptohome_keys_manager)
      << "Crypto wanted to use CryptohomeKeysManager but was not provided";
  CHECK(tpm) << "Crypto wanted to use Tpm but was not provided";
  if (tpm_ == NULL) {
    tpm_ = tpm;
  }
  cryptohome_keys_manager_ = cryptohome_keys_manager;
  cryptohome_keys_manager_->Init();
  if (tpm_->GetLECredentialBackend() &&
      tpm_->GetLECredentialBackend()->IsSupported()) {
    le_manager_ = std::make_unique<LECredentialManagerImpl>(
        tpm_->GetLECredentialBackend(), base::FilePath(kSignInHashTreeDir));
  }
  return true;
}

CryptoError Crypto::EnsureTpm(bool reload_key) const {
  CryptoError result = CryptoError::CE_NONE;
  if (tpm_ && cryptohome_keys_manager_) {
    if (reload_key || !cryptohome_keys_manager_->HasAnyCryptohomeKey()) {
      cryptohome_keys_manager_->Init();
    }
  }
  return result;
}

bool Crypto::GetOrCreateSalt(const FilePath& path,
                             size_t length,
                             bool force,
                             SecureBlob* salt) const {
  int64_t file_len = 0;
  if (platform_->FileExists(path)) {
    if (!platform_->GetFileSize(path, &file_len)) {
      LOG(ERROR) << "Can't get file len for " << path.value();
      return false;
    }
  }
  SecureBlob local_salt;
  if (force || file_len == 0 || file_len > kSystemSaltMaxSize) {
    LOG(ERROR) << "Creating new salt at " << path.value() << " (" << force
               << ", " << file_len << ")";
    // If this salt doesn't exist, automatically create it.
    local_salt = CreateSecureRandomBlob(length);
    if (!platform_->WriteSecureBlobToFileAtomicDurable(path, local_salt,
                                                       kSaltFilePermissions)) {
      LOG(ERROR) << "Could not write user salt";
      return false;
    }
  } else {
    local_salt.resize(file_len);
    if (!platform_->ReadFileToSecureBlob(path, &local_salt)) {
      LOG(ERROR) << "Could not read salt file of length " << file_len;
      return false;
    }
  }
  if (salt) {
    salt->swap(local_salt);
  }
  return true;
}

void Crypto::PasswordToPasskey(const char* password,
                               const brillo::SecureBlob& salt,
                               SecureBlob* passkey) {
  CHECK(password);

  std::string ascii_salt = SecureBlobToHex(salt);
  // Convert a raw password to a password hash
  SHA256_CTX sha_context;
  SecureBlob md_value(SHA256_DIGEST_LENGTH);

  SHA256_Init(&sha_context);
  SHA256_Update(&sha_context, ascii_salt.data(), ascii_salt.length());
  SHA256_Update(&sha_context, password, strlen(password));
  SHA256_Final(md_value.data(), &sha_context);

  md_value.resize(SHA256_DIGEST_LENGTH / 2);
  SecureBlob local_passkey(SHA256_DIGEST_LENGTH);
  SecureBlobToHexToBuffer(md_value, local_passkey.data(), local_passkey.size());
  passkey->swap(local_passkey);
}

bool Crypto::NeedsPcrBinding(const uint64_t& label) const {
  DCHECK(le_manager_)
      << "le_manage_ doesn't exist when calling NeedsPcrBinding()";
  return le_manager_->NeedsPcrBinding(label);
}

bool Crypto::ResetLECredential(const VaultKeyset& vk_reset,
                               const VaultKeyset& vk,
                               CryptoError* error) const {
  if (!tpm_) {
    return false;
  }

  // Bail immediately if we don't have a valid LECredentialManager.
  if (!le_manager_) {
    LOG(ERROR) << "Attempting to Reset LECredential on a platform that doesn't "
                  "support LECredential";
    PopulateError(error, CryptoError::CE_LE_NOT_SUPPORTED);
    return false;
  }

  if (!vk_reset.IsLECredential()) {
    LOG(ERROR) << "vk_reset is not an LE credential.";
    PopulateError(error, CryptoError::CE_LE_FLAGS_AND_POLICY_MISMATCH);
    return false;
  }

  SecureBlob local_reset_seed(vk.GetResetSeed().begin(),
                              vk.GetResetSeed().end());
  SecureBlob reset_salt(vk_reset.GetResetSalt().begin(),
                        vk_reset.GetResetSalt().end());
  if (local_reset_seed.empty() || reset_salt.empty()) {
    LOG(ERROR) << "Reset seed/salt is empty, can't reset LE credential.";
    PopulateError(error, CryptoError::CE_OTHER_FATAL);
    return false;
  }

  SecureBlob reset_secret = HmacSha256(reset_salt, local_reset_seed);
  int ret = le_manager_->ResetCredential(vk_reset.GetLELabel(), reset_secret);
  if (ret != LE_CRED_SUCCESS) {
    PopulateError(error, ret == LE_CRED_ERROR_INVALID_RESET_SECRET
                             ? CryptoError::CE_LE_INVALID_SECRET
                             : CryptoError::CE_OTHER_FATAL);
    return false;
  }
  return true;
}

int Crypto::GetWrongAuthAttempts(uint64_t le_label) const {
  DCHECK(le_manager_)
      << "le_manage_ doesn't exist when calling GetWrongAuthAttempts()";
  return le_manager_->GetWrongAuthAttempts(le_label);
}

bool Crypto::RemoveLECredential(uint64_t label) const {
  if (!tpm_) {
    LOG(WARNING) << "No TPM instance for RemoveLECredential.";
    return false;
  }

  // Bail immediately if we don't have a valid LECredentialManager.
  if (!le_manager_) {
    LOG(ERROR) << "No LECredentialManager instance for RemoveLECredential.";
    return false;
  }

  return le_manager_->RemoveCredential(label) == LE_CRED_SUCCESS;
}

bool Crypto::is_cryptohome_key_loaded() const {
  if (tpm_ == NULL || cryptohome_keys_manager_ == NULL) {
    return false;
  }
  return cryptohome_keys_manager_->HasAnyCryptohomeKey();
}

bool Crypto::CanUnsealWithUserAuth() const {
  return false;
}

}  // namespace cryptohome
