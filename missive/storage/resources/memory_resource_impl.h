// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_STORAGE_RESOURCES_MEMORY_RESOURCE_IMPL_H_
#define MISSIVE_STORAGE_RESOURCES_MEMORY_RESOURCE_IMPL_H_

#include <atomic>
#include <cstdint>

#include "missive/storage/resources/resource_interface.h"

namespace reporting {

// Interface to resources management by Storage module.
// Must be implemented by the caller base on the platform limitations.
// All APIs are non-blocking.
class MemoryResourceImpl : public ResourceInterface {
 public:
  MemoryResourceImpl();
  ~MemoryResourceImpl() override;

  // Implementation of ResourceInterface methods.
  bool Reserve(uint64_t size) override;
  void Discard(uint64_t size) override;
  uint64_t GetTotal() override;
  uint64_t GetUsed() override;
  void Test_SetTotal(uint64_t test_total) override;

 private:
  uint64_t total_;
  std::atomic<uint64_t> used_;
};

}  // namespace reporting

#endif  // MISSIVE_STORAGE_RESOURCES_MEMORY_RESOURCE_IMPL_H_
