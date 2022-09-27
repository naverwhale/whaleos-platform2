// Copyright (c) 2022 NAVER Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/whaleos_util.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_util.h>

namespace brillo {

bool IsWhalebook2Model() {
  std::string product_name;
  base::FilePath file_path("/sys/class/dmi/id/product_name");
  std::string file_content;

  if (!base::ReadFileToString(file_path, &file_content)) {
    return false;
  }

  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, &product_name);

  static const std::string kModelNameStartings[] = {
    "14T30Q",
    "14TN30Q",
    "14TW30Q",
  };
  for (size_t i = 0; i < base::size(kModelNameStartings); i++) {
    if (base::StartsWith(product_name, kModelNameStartings[i])) {
      return true;
    }
  }

  return false;
}

}  // namespace brillo
