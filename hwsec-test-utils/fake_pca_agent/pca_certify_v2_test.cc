// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/pca_certify_v2.h"

#include <memory>
#include <string>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace hwsec_test_utils {

namespace {
// A cert request from a real DUT.
constexpr char kCertRequestInHex[] =
    "0ABE043082023A308201220202250F300D06092A864886F70D01010505003048310B300906"
    "035504061302435231253023060355040A0C1C4174746573746174696F6E204C6F63616C20"
    "5465737420496E6672613112301006035504030C096C6F63616C686F7374301E170D323030"
    "3531343038313830325A170D3230303531353038313830325A3048310B3009060355040613"
    "02435231253023060355040A0C1C4174746573746174696F6E204C6F63616C205465737420"
    "496E6672613112301006035504030C096C6F63616C686F73743059301306072A8648CE3D02"
    "0106082A8648CE3D03010703420004595CE669CD3D9A3B5D9CBF88EA41685C60F192F2F6CF"
    "89B92B4897C200671C397D25EB6CDD7D4D88492EAC63916C910A3C20B5253A5E98015CB002"
    "FD873FC8B8300D06092A864886F70D0101050500038201010044344BC56105A008C14792AF"
    "16446A589BE252922655438DF1EBF1B485A9A9D329A6A76DED829C9CC49CA159F592DBD8E6"
    "0E52FA508016DFBC9947B77A43EEE65DB099F29ECEBE7FEC0AC20C085D52FE37E8F2852839"
    "1A44D12ED776B18D9DDB5CF9F28AD4EB86756321A88EE0416E19E89F3B807882B7C1EC1536"
    "B1311AC2E6B1305E4C6494B034F6A14EFB810ECE852B7341FDD66AAAA688DFB98148EED002"
    "6C4BE88859A603C01B39EB3A2A0DBF92411DF93F7E40F343F69B75E0CB234B15FC86AB38D2"
    "18A0E6F87A6D8A3E92CF4AEBC983D9542BBFD7CAD9C7F9FA56035C702E61A5FFFECE6EA5A5"
    "3D60AB80F42CB60EFF67EF14C381513B8922F6003F271A96020001000B0004047200000010"
    "00100800000000000100BCD564598AB9CA22DF5976CB6E0C6A54BEA3E423C063B707C14A9C"
    "12FEFDE1DE4B5A466A820F96722B55C9A8C20AEA5BE87E0B2CCA952B768BE66B4C2A0932CF"
    "456B8F781BEB781B742A9CF2B78DC6CD4A3E77079FA6FBE1A95A8A46F0F4F90DCD93B4DF71"
    "5BCDDF39C3FC2A04BE3A6C23A283BFDF6340981EEB1A4325AD09CC7D7447EA4D9FD4345043"
    "CB43E0E895E7A1E687D4C6A81DDEB3597851CB821597E3BF3BFF831E4B4A8C97446C296B9A"
    "059DF9E31D7ED1F4C89912CC367F1793AA5E6D17E8B74DFE7F2C028638F92FBED040CE0A24"
    "19720646C716B328157DA4E972826DE41A7445972807C8472849A0DB2FE756552AFB8D0D89"
    "F1D4631E478F6922A101FF54434780170022000B683E138E6F387DE1C238C1CB7EEBA04807"
    "4AF34DA49E54CEEAC1F415260AD1CE00143B04E4AB59D6FCFE4D208C818A6EC5A6D55B543C"
    "02BF6B73A4BADEB0AA475B04AF956FAA01FE7D8A21EBAE8F1E0022000BCE44882446451FD3"
    "BB7D9BD3F16FD717B9EAD32BD18CF391C7BE46F839CF30260022000B15CAB16007E29654A9"
    "E6059A566BA716EB22EC989A63A14E529CB8EF0CE35AB12A473045022036F49EE597116C24"
    "E41CAE491D9BE248833FE6948520259593D4190AD1E755A4022100CD1339072B90EFF7F0A6"
    "26E9FCEF74EA8142E823D5865F41B5E3E286370B82645214898D625D003C32C0BF31F47F8E"
    "A91CE36328D10E58017002";
}  // namespace

class PcaCertifyV2Test : public testing::Test {
 public:
  PcaCertifyV2Test() {
    SetupCertRequestToVerify();
    pca_certify_ = std::make_unique<fake_pca_agent::PcaCertifyV2>(request_);
  }
  ~PcaCertifyV2Test() override = default;

 protected:
  attestation::AttestationCertificateRequest request_;
  std::unique_ptr<fake_pca_agent::PcaCertifyV2> pca_certify_;

  void SetupCertRequestToVerify() {
    std::vector<uint8_t> output;
    ASSERT_TRUE(base::HexStringToBytes(kCertRequestInHex, &output));
    ASSERT_TRUE(
        request_.ParseFromString(std::string(output.begin(), output.end())));
  }
};

TEST_F(PcaCertifyV2Test, Certify) {
  EXPECT_TRUE(pca_certify_->Preprocess());
  EXPECT_TRUE(pca_certify_->Verify());
  EXPECT_TRUE(pca_certify_->Generate());
}

}  // namespace hwsec_test_utils
