// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/lockbox-cache.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>

#include <gtest/gtest.h>

namespace cryptohome {
namespace {

constexpr uint8_t kInvalid[] = {0xba, 0xad};
constexpr uint8_t kNvram[] = {
    0x00, 0x00, 0x00, 0xe0, 0x00, 0xb8, 0x1a, 0xa2, 0xd7, 0xd1, 0xc1, 0xfc,
    0x92, 0x13, 0x05, 0xed, 0xa7, 0x90, 0x3a, 0x68, 0xfa, 0x9c, 0xe3, 0xa7,
    0x15, 0x52, 0xdf, 0xf3, 0x96, 0x59, 0x3c, 0xa5, 0x9e, 0xf2, 0x87, 0x8b,
    0xec, 0x4a, 0x43, 0xf6, 0x48, 0x3f, 0xcb, 0x92, 0xd4, 0x26, 0x99, 0xdd,
    0x34, 0x2a, 0xb5, 0x38, 0xf0, 0x8a, 0x8c, 0x45, 0x05, 0x65, 0xc6, 0x1d,
    0x1f, 0x11, 0x14, 0x04, 0x4d, 0x3c, 0x81, 0xf2, 0x89,
};
constexpr uint8_t kLockbox[] = {
    0x08, 0x01, 0x12, 0x1f, 0x0a, 0x1a, 0x63, 0x6f, 0x6e, 0x73, 0x75, 0x6d,
    0x65, 0x72, 0x2e, 0x61, 0x70, 0x70, 0x5f, 0x6b, 0x69, 0x6f, 0x73, 0x6b,
    0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x01, 0x00, 0x12,
    0x19, 0x0a, 0x10, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x70, 0x72, 0x69, 0x73,
    0x65, 0x2e, 0x6f, 0x77, 0x6e, 0x65, 0x64, 0x12, 0x05, 0x74, 0x72, 0x75,
    0x65, 0x00, 0x12, 0x1e, 0x0a, 0x0f, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x70,
    0x72, 0x69, 0x73, 0x65, 0x2e, 0x6d, 0x6f, 0x64, 0x65, 0x12, 0x0b, 0x65,
    0x6e, 0x74, 0x65, 0x72, 0x70, 0x72, 0x69, 0x73, 0x65, 0x00, 0x12, 0x2a,
    0x0a, 0x11, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x70, 0x72, 0x69, 0x73, 0x65,
    0x2e, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x15, 0x63, 0x68, 0x72,
    0x6f, 0x6d, 0x65, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x74, 0x65, 0x73,
    0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x12, 0x15, 0x0a, 0x10, 0x65, 0x6e,
    0x74, 0x65, 0x72, 0x70, 0x72, 0x69, 0x73, 0x65, 0x2e, 0x72, 0x65, 0x61,
    0x6c, 0x6d, 0x12, 0x01, 0x00, 0x12, 0x3d, 0x0a, 0x14, 0x65, 0x6e, 0x74,
    0x65, 0x72, 0x70, 0x72, 0x69, 0x73, 0x65, 0x2e, 0x64, 0x65, 0x76, 0x69,
    0x63, 0x65, 0x5f, 0x69, 0x64, 0x12, 0x25, 0x32, 0x63, 0x34, 0x37, 0x37,
    0x36, 0x35, 0x33, 0x2d, 0x32, 0x61, 0x66, 0x66, 0x2d, 0x34, 0x64, 0x63,
    0x35, 0x2d, 0x62, 0x32, 0x34, 0x30, 0x2d, 0x62, 0x38, 0x31, 0x34, 0x35,
    0x66, 0x31, 0x36, 0x33, 0x66, 0x66, 0x62, 0x00,
};

class LockboxCacheTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());
    nvram_path_ = tmpdir_.GetPath().AppendASCII("nvram");
    lockbox_path_ = tmpdir_.GetPath().AppendASCII("lockbox");
    cache_path_ = tmpdir_.GetPath().AppendASCII("cache");
  }

  template <typename Array>
  void WriteBlob(const base::FilePath& path, const Array& array) {
    ASSERT_TRUE(platform_.WriteFile(
        path, brillo::Blob(std::begin(array), std::end(array))));
  }

  void ExpectFailure() {
    EXPECT_FALSE(
        CacheLockbox(&platform_, nvram_path_, lockbox_path_, cache_path_));
    EXPECT_FALSE(base::PathExists(cache_path_));
  }

  cryptohome::Platform platform_;
  base::ScopedTempDir tmpdir_;
  base::FilePath nvram_path_;
  base::FilePath lockbox_path_;
  base::FilePath cache_path_;
};

TEST_F(LockboxCacheTest, NoNvram) {
  ExpectFailure();
}

TEST_F(LockboxCacheTest, InvalidNvram) {
  WriteBlob(nvram_path_, kInvalid);
  ExpectFailure();
}

TEST_F(LockboxCacheTest, NoLockbox) {
  WriteBlob(nvram_path_, kNvram);
  ExpectFailure();
}

TEST_F(LockboxCacheTest, LockboxVerificationBadSize) {
  WriteBlob(nvram_path_, kNvram);
  WriteBlob(lockbox_path_, kInvalid);
  ExpectFailure();
}

TEST_F(LockboxCacheTest, LockboxVerificationBadData) {
  WriteBlob(nvram_path_, kNvram);
  uint8_t invalid_lockbox[sizeof(kLockbox)];
  for (size_t i = 0; i < sizeof(invalid_lockbox); ++i) {
    invalid_lockbox[i] ^= 0xff;
  }
  WriteBlob(lockbox_path_, invalid_lockbox);
  ExpectFailure();
}

TEST_F(LockboxCacheTest, Success) {
  WriteBlob(nvram_path_, kNvram);
  WriteBlob(lockbox_path_, kLockbox);

  EXPECT_TRUE(
      CacheLockbox(&platform_, nvram_path_, lockbox_path_, cache_path_));
  brillo::Blob cache;
  ASSERT_TRUE(platform_.ReadFile(cache_path_, &cache));
  EXPECT_EQ(brillo::Blob(std::begin(kLockbox), std::end(kLockbox)), cache);
}

}  // namespace
}  // namespace cryptohome
