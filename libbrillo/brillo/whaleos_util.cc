// Copyright (c) 2022 NAVER Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/whaleos_util.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_util.h>

namespace {

constexpr char kProductNameFile[] =
    "/sys/class/dmi/id/product_name";
constexpr char kBiosVersionFile[] =
    "/sys/class/dmi/id/bios_version";

}  // namespace

namespace brillo {

std::string GetBiosVersion() {
  base::FilePath file_path(kBiosVersionFile);
  std::string bios_version;
  std::string file_content;

  base::ReadFileToString(file_path, &file_content);
  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, &bios_version);

  return bios_version;
}

std::string GetProductName() {
  base::FilePath file_path(kProductNameFile);
  std::string product_name;
  std::string file_content;

  base::ReadFileToString(file_path, &file_content);
  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, &product_name);

  return product_name;
}

bool IsWhalebook2Model() {
  std::string product_name = GetProductName();

  static const std::string kModelNameStartings[] = {
    "14T30Q",
    "14TN30Q",
    "14TW30Q",
    "14TN30S",
    "14TW30S",
  };
  for (size_t i = 0; i < std::size(kModelNameStartings); i++) {
    if (base::StartsWith(product_name, kModelNameStartings[i])) {
      return true;
    }
  }

  return false;
}

}  // namespace brillo
