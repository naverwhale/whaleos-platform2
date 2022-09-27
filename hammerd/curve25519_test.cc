// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Ported from ChromeOS EC repository.
// https://chromium.googlesource.com/chromiumos/platform/ec/+/\
// 136a80e1138633c2f2ac249c15078b587af9c7ec/test/x25519.c
//
// Changed item:
// - Use Google Test as unittest framework.

#include <string.h>

#include <base/logging.h>
#include <gtest/gtest.h>

#include "hammerd/curve25519.h"

// Define this to test 1 million iterations of x25519 (takes up to
// a few minutes on host, up to a few days on microcontroller).
#undef TEST_X25519_1M_ITERATIONS

namespace hammerd {

TEST(X25519Test, scalar) {
  // Taken from https://tools.ietf.org/html/rfc7748#section-5.2
  static const uint8_t scalar1[32] = {
      0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15,
      0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc,
      0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
  };
  static const uint8_t point1[32] = {
      0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1,
      0xa4, 0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3,
      0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
  };
  static const uint8_t expected1[32] = {
      0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea,
      0x4d, 0xf2, 0x8d, 0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c,
      0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
  };
  static const uint8_t scalar2[32] = {
      0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26,
      0x91, 0x95, 0x7d, 0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea,
      0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d,
  };
  static const uint8_t point2[32] = {
      0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95,
      0x9d, 0x05, 0x38, 0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0,
      0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93,
  };
  static const uint8_t expected2[32] = {
      0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4,
      0x5c, 0xb4, 0xb8, 0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f,
      0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57,
  };
  uint8_t out[32];

  X25519(out, scalar1, point1);
  EXPECT_EQ(0, memcmp(expected1, out, sizeof(out)));

  X25519(out, scalar2, point2);
  EXPECT_EQ(0, memcmp(expected2, out, sizeof(out)));
}

TEST(X25519Test, small_order) {
  static const uint8_t kSmallOrderPoint[32] = {
      0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
      0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
      0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8,
  };
  uint8_t out[32], private_key[32];

  memset(private_key, 0x11, sizeof(private_key));
  EXPECT_FALSE(X25519(out, private_key, kSmallOrderPoint));
}

TEST(X25519Test, iterated) {
  // Taken from https://tools.ietf.org/html/rfc7748#section-5.2
  static const uint8_t expected_1K[32] = {
      0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55, 0x28, 0x00, 0xef,
      0x56, 0x6f, 0x2f, 0x4d, 0x3c, 0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60,
      0xe3, 0x87, 0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51,
  };
#ifdef TEST_X25519_1M_ITERATIONS
  static const uint8_t expected_1M[32] = {
      0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd, 0x86, 0x44, 0x97,
      0x29, 0x7e, 0x57, 0x5e, 0x6f, 0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c,
      0x30, 0xdf, 0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24};
#endif
  uint8_t scalar[32] = {9}, point[32] = {9}, out[32];
  unsigned i;

  for (i = 0; i < 1000; i++) {
    X25519(out, scalar, point);
    memcpy(point, scalar, sizeof(point));
    memcpy(scalar, out, sizeof(scalar));
  }
  EXPECT_EQ(0, memcmp(expected_1K, scalar, sizeof(expected_1K)));

#ifdef TEST_X25519_1M_ITERATIONS
  for (; i < 1000000; i++) {
    X25519(out, scalar, point);
    memcpy(point, scalar, sizeof(point));
    memcpy(scalar, out, sizeof(scalar));
    if ((i % 10000) == 0) {
      LOG(INFO) << "Iteration: " << i;
    }
  }
  EXPECT_EQ(0, memcmp(expected_1M, scalar, sizeof(expected_1M)));
#endif
}

}  // namespace hammerd
