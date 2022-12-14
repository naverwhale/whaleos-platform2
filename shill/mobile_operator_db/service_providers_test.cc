// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <set>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/macros.h>
#include <google/protobuf/repeated_field.h>
#include <gtest/gtest.h>

#include "shill/mobile_operator_db/mobile_operator_db.pb.h"
#include "shill/protobuf_lite_streams.h"

using testing::Test;

namespace shill {

using MvnoMnoPair =
    std::pair<const shill::mobile_operator_db::MobileVirtualNetworkOperator*,
              const shill::mobile_operator_db::MobileNetworkOperator*>;

class ServiceProvidersTest : public testing::Test {
 protected:
  // Per-test-suite set-up.
  // Called before the first test in this test suite.
  static void SetUpTestSuite() {
    const char* out_dir = getenv("OUT");
    CHECK_NE(out_dir, nullptr);
    base::FilePath database_path =
        base::FilePath(out_dir).Append("serviceproviders.pbf");
    const char* database_path_cstr = database_path.value().c_str();
    std::unique_ptr<google::protobuf::io::CopyingInputStreamAdaptor>
        database_stream;
    database_stream.reset(protobuf_lite_file_input_stream(database_path_cstr));
    ASSERT_NE(database_stream, nullptr);
    database_ = std::make_unique<shill::mobile_operator_db::MobileOperatorDB>();
    ASSERT_TRUE(database_->ParseFromZeroCopyStream(database_stream.get()));

    // Load all MVNOs into a vector with their MNO as a secondary variable for
    // easy iteration.
    for (const auto& mno : database_->mno()) {
      for (const auto& mvno : mno.mvno()) {
        MvnoMnoPair mvno_pair(&mvno, &mno);
        mvnos_.push_back(mvno_pair);
      }
    }
    for (const auto& mvno : database_->mvno()) {
      MvnoMnoPair mvno_pair(&mvno, nullptr);
      mvnos_.push_back(mvno_pair);
    }
  }
  // Per-test-suite tear-down.
  // Called after the last test in this test suite.
  static void TearDownTestSuite() {
    database_.reset();
    database_ = nullptr;
    mvnos_.clear();
  }

  // Expensive resource shared by all tests.
  static std::unique_ptr<mobile_operator_db::MobileOperatorDB> database_;
  static std::vector<MvnoMnoPair> mvnos_;
};

std::unique_ptr<mobile_operator_db::MobileOperatorDB>
    ServiceProvidersTest::database_ = nullptr;
std::vector<MvnoMnoPair> ServiceProvidersTest::mvnos_;

TEST_F(ServiceProvidersTest, CheckUniqueUUIDs) {
  // Verify that we are not using the same uuid for different MNOs/MVNOs.
  // This is a common mistake when copy/pasting carrier info.
  std::set<std::string> uuids;
  for (const auto& mno : database_->mno()) {
    ASSERT_TRUE(mno.data().has_uuid());
    EXPECT_EQ(uuids.count(mno.data().uuid()), 0)
        << "Non unique uuid: " << mno.data().uuid();
    uuids.emplace(mno.data().uuid());
  }
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    ASSERT_TRUE(mvno->data().has_uuid());
    EXPECT_EQ(uuids.count(mvno->data().uuid()), 0)
        << "Non unique uuid: " << mvno->data().uuid();
    uuids.emplace(mvno->data().uuid());
  }
}

TEST_F(ServiceProvidersTest, CheckRootLevelMvnosWithoutFilters) {
  // If a MVNO is at the root level(not under an MNO), and there is no filter
  // in it, the MVNO will always be selected.
  for (const auto& mvno : database_->mvno()) {
    EXPECT_TRUE(mvno.mvno_filter_size() > 0)
        << "MVNO with uuid: " << mvno.data().uuid()
        << " does not have a filter.";
  }
}

TEST_F(ServiceProvidersTest, CheckIMSIMatchesMCCMNC) {
  // Verify that the IMSI values start with one of the MCCMNC values.
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    auto mno = mvno_mno_pair.second;
    for (const auto& filter : mvno->mvno_filter()) {
      if (filter.type() == mobile_operator_db::Filter_Type_IMSI) {
        // Combine MNO and MVNO MCCMNCs
        std::set<std::string> mccmncs;
        for (const auto& mccmnc : mvno->data().mccmnc())
          mccmncs.insert(mccmnc);
        if (mno)
          for (const auto& mccmnc : mno->data().mccmnc())
            mccmncs.insert(mccmnc);

        // Validate ranges
        for (auto range : filter.range()) {
          bool found_match = false;
          for (const auto& mccmnc : mccmncs) {
            if (std::to_string(range.start()).rfind(mccmnc, 0) == 0 &&
                std::to_string(range.end()).rfind(mccmnc, 0) == 0) {
              found_match = true;
              break;
            }
          }
          EXPECT_TRUE(found_match)
              << "IMSI range " << range.start() << "-" << range.end()
              << " doesn't match any MCCMNCs in that MVNO.";
        }
        // Validate regex for simple cases:
        // - Regex that starts with 5 numeric characters.
        if (mccmncs.size() > 0 && filter.has_regex() &&
            filter.regex().size() >= 5 &&
            (filter.regex().substr(0, 5).find_first_not_of("0123456789") ==
             std::string::npos)) {
          bool found_match = false;
          for (const auto& mccmnc : mccmncs) {
            if (filter.regex().rfind(mccmnc, 0) == 0) {
              found_match = true;
              break;
            }
          }
          EXPECT_TRUE(found_match)
              << "IMSI regex " << filter.regex()
              << " doesn't match any MCCMNCs in that MVNO.";
        }
      }
    }
  }
}

TEST_F(ServiceProvidersTest, CheckIMSIRangesAreValid) {
  // Verify that different IMSI ranges don't overlap.
  // Verify that the IMSI ranges are valid(start<end).
  std::map<uint64_t, uint64_t> ranges;
  for (auto mvno_mno_pair : mvnos_) {
    auto mvno = mvno_mno_pair.first;
    for (const auto& filter : mvno->mvno_filter()) {
      if (filter.type() == mobile_operator_db::Filter_Type_IMSI) {
        for (auto range : filter.range()) {
          EXPECT_LT(range.start(), range.end());
          ASSERT_EQ(ranges.count(range.start()), 0);
          EXPECT_GT(range.start(), 0);
          EXPECT_GT(range.end(), 0);
          // Insert all ranges into |ranges| and process them later
          ranges[range.start()] = range.end();
        }
      }
    }
  }
  uint64_t previous_start = 0;
  uint64_t previous_end = 0;
  for (const auto& range : ranges) {
    if (previous_end > 0) {
      EXPECT_GT(range.first, previous_end)
          << " The IMSI ranges " << previous_start << ":" << previous_end
          << " and " << range.first << ":" << range.second << " overlap.";
    }
    previous_start = range.first;
    previous_end = range.second;
  }
}

}  // namespace shill
