// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/pca_certify_v1.h"

#include <memory>
#include <vector>

#include <base/optional.h>
#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace hwsec_test_utils {

namespace {
// A cert request from a real DUT.
constexpr char kCertRequestInHex[] =
    "0A890630820305308201ED0202250F300D06092A864886F70D01010505003048310B300906"
    "035504061302435231253023060355040A0C1C4174746573746174696F6E204C6F63616C20"
    "5465737420496E6672613112301006035504030C096C6F63616C686F7374301E170D323030"
    "3531323039313032305A170D3230303531333039313032305A3048310B3009060355040613"
    "02435231253023060355040A0C1C4174746573746174696F6E204C6F63616C205465737420"
    "496E6672613112301006035504030C096C6F63616C686F737430820122300D06092A864886"
    "F70D01010105000382010F003082010A028201010092B0082F981D839323B73F98D4294161"
    "2C0D2B890AD3C2DCB5E94CFF8518A34E67ADD539B7EC6E81AFD19D9408B37CA49405F62B4C"
    "A8E8B6A7F3B07E13222A0BADDDFDA90B34B31E0D8B3FFE2C44D15F9432C193E5AE17CA0BB2"
    "6A341E4ECFF261C06179D95890956F4D99FB17F96C4F976AAADD39C9E5C49AEB7D169E768D"
    "BCEE3B58E7CB0CD5EA20769E24E40F791F15791367C732EE88BAD9B4087FBCDC0A97ECE9C1"
    "8BEA47763753A426E0F37E7B675CE4C9090555AF49B9ED8121252811A193AA57964C200920"
    "559A7041EEF758C67BCAFC1CAD3A33F8394E79C65143FF1DCB517BB74107E4FAA6BC21291B"
    "3D61F903F155635E91E9DC2142B7C510902F0203010001300D06092A864886F70D01010505"
    "00038201010022E895F864D608A50D82337A067187500325963F6F5E25ECCFF09A39F982FC"
    "15FDB5CC75F2C0ACFF7E612878B54B572278DF17F896FA95AB4217C5B728BE8DA99E56153B"
    "31BFC83D23D4F0F998A4B4DEAC67A890393316933AB6FAA5DE6DB17A1C91BC129B9CC48562"
    "D3B3418E66DE406643E95D780EB7683866D251E114AC2EF567F9882575A48EE669264DAE2F"
    "0BE8FFDE8EDE875278DD7D2134A9043AF1C83D21145DA903F398405F0919A0D3BD6D6F7FD0"
    "05360AE0888B339E91532C51D1C688E2DBB85AD3ED81DDB9D7F014FFD07BC77410A4825831"
    "7A072B2ACCE25A3A2275A958607B49833FCC601094EB2FB8093DC546D90E3B69D36C06C58E"
    "960C4B1A9C0200000001000100030000000C000008000000000200000000000001009B008E"
    "46826EC16917F220697D5DDCFAB8EF42069CB1F5727F3BC53369095CFAD52B86BD306A810A"
    "C94C974047D810970B7D47A150F6C22B26B877E727C2B064014D2A22C07B14CB3861AB64F3"
    "4393E0EF5AFAC42AE343D258A21E7A5B6D4B55C938F884A91E4C60C15BAF249A1DF9589AE4"
    "A7EC4908E65D9D80221D9AA3517596D8163F671F152E4633F8F239C251A3C00037BEC555F5"
    "FFD046DCC8301A3F043CBE0B5970766FF88DD6768A01F4B0A50F08EF8F816D371DA9FF971E"
    "EFE61D930590DCD863500E76F4728A4D755AA5F6A05FE291A8443C11877DA1469573540970"
    "499E86EBC3DA4D7E365CAE8C3AE267681599463A03F7A4550406AF81B3CAD9225001010000"
    "0010000000040000000001000100030000000C00000800000000020000000087964185DFDB"
    "E96B6007839BF55706B4837D93F97C738D3208C9AD775FD27E0C9724DFFF808741B5000000"
    "00002A80024C113AE92D6B884DE0D788E0D91FC7D903FB3F9558C15BF4F4BDB88C9B1232EA"
    "841A78A6978C6ECB94B207E1E132160D1799A0B422702D637FB547233CD1B52E3A7EBC020B"
    "1C146D3E0F51FF617C728382212275B3BA3532A4F68189760A55805F39FCA7F9A6575BC823"
    "807C8E4A69C20A8281099ADEAD0EC4D7D6BF7936846C461BDE24F790C4A25BDBE4ADBB9FB5"
    "79219D5B151A445F2CEDC1A572D588C1F5C63F26F326AD1BE86C47C7922EA803A75D4BA0B8"
    "799A3FF85D5CB1EC3B1C67B9EFFB375A32B63012C0BD4839C68D7851FC954627EB3FEFBE55"
    "699F6AC35BD7D8C864B618675BAB5DF4BDB9BB01183752BA48AE2282882A7AE1399E8B14B7"
    "2C41521416C740AAE3FFD94CAEB2D56E22914190239B5E7758017001";

}  // namespace

class PcaCertifyV1Test : public testing::Test {
 public:
  PcaCertifyV1Test() {
    SetupCertRequestToVerify();
    pca_certify_ = std::make_unique<fake_pca_agent::PcaCertifyV1>(request_);
  }
  ~PcaCertifyV1Test() override = default;

 protected:
  attestation::AttestationCertificateRequest request_;
  std::unique_ptr<fake_pca_agent::PcaCertifyV1> pca_certify_;

  void SetupCertRequestToVerify() {
    std::vector<uint8_t> output;
    ASSERT_TRUE(base::HexStringToBytes(kCertRequestInHex, &output));
    ASSERT_TRUE(
        request_.ParseFromString(std::string(output.begin(), output.end())));
  }
};

TEST_F(PcaCertifyV1Test, Certify) {
  EXPECT_TRUE(pca_certify_->Preprocess());
  EXPECT_TRUE(pca_certify_->Verify());
  EXPECT_TRUE(pca_certify_->Generate());
}

}  // namespace hwsec_test_utils
