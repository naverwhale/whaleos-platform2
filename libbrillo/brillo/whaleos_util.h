// Copyright (c) 2022 NAVER Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_WHALEOS_UTIL_H_
#define LIBBRILLO_BRILLO_WHALEOS_UTIL_H_

#include <brillo/brillo_export.h>

namespace brillo {

constexpr static char kTpmOwnedFallbackPath[] = "/var/.tpm_owned";

BRILLO_EXPORT bool IsWhalebook2Model();

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_WHALEOS_UTIL_H_
