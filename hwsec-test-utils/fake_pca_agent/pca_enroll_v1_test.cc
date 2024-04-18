// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/pca_enroll_v1.h"

#include <memory>
#include <string>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace hwsec_test_utils {

namespace {
// A real challenge response from a developer-mode device.
constexpr char kEnrollRequestInHex[] =
    "0AE10C12800291D78402ACFFEF69CD5C07739AE8D27CF73CCFF6C951844E8CB1BB0298DF69"
    "3F6A17C73285FD5B98AE0E0376D287DFCCC4CE15A76F9AEECE550E1CCAAC21D5281928A869"
    "C5CB5E068E255274A59C210A220B4DF15664EACD7739B94C599E25B2366B53DB2CAA3A0CD1"
    "6FFEEE58AD0E2EFEE8B3ECFD81EC76BD9E912DAA7C5A09CED0EC771B9D6FBCC0C53790098A"
    "63F30E9DB701B7D01A093E9D3382C545DA8A449FEEF60C7B3AE5D570204E4FBBF97F982466"
    "1F81D3EA397637F052631AE44289DAB1ACCD742EEC673A1DAF39093186C890C9859A2B6C65"
    "E1CF9068E32B15E4ADEE86F283E09ED868FB4577E1FE107F1A84471AD6BF00B9C3BE508CFC"
    "E597871A108CA75ADABF2D984F15058A78859CF2972240F9F9FFF29B6D6D1D9B4AF27ABF08"
    "59436F762A05E533102BCEBB30B88200E487C0BCBF7BE8CBCD294E450E6B68383C29C02977"
    "BB7560F8418CE5871E9463F8652A800AC9ADDA3834F84E1BF769A6E2AE9F7C4367D8AAAB60"
    "58D7CAC407B743F23DB68E6B95A8034BF405FAA99EC6B8DD0D1DE23287EFA0959B6D690ED7"
    "59429705A06FC9B0B018179F48C0D0BFC5CC15B457163EA3EF59ED0A9A3BDDC091D0AEF2A5"
    "0B3B9A05DEAC4CC23A7D6FF70636A2CD4698F3653A9737E28F719023586DFB8F3882DC834A"
    "80593F8F2919D49830FAC3B6E394BB1C663FB7DC658C2C45B9F52514B1B22984BAD9A9976F"
    "1226FDB2158C38631A3B9422C2F72676B613528C5FDEF0614CBECBB27539C5CC9C04D612D1"
    "83126F1201AA072686B1CFE0AD6EC0F273FEB5A5505176A6792B926FBE2DB5ECD5CC5AD7AF"
    "663974C2DD38A751B42AC01533B1EAAAAA7CAF6E98F8ABBB2E56C187AF9AA341B01D4F2A5A"
    "4F03C58FF51F8D29AB8CCBC576EB672AA0C4C851433D9020CA5821F721C129F7AC10B33738"
    "B90BFFDDBE65E84F02A01BF2DCD56932488BE5F76378B96FA13CDDE508FA03A9ED2BBC0B7C"
    "B71E94E30356685E1DDE922EC02AC95D504413E7164153CDB4E1E41D3DF3E7CED1D2361E99"
    "19704952464473AEE8AC18877CAC9025129B118FE68383C64F30BD49EF24A9EA1C5DC1F3BB"
    "1469E932C1516F5566C81F843EE1EE53FD689959D5FB0C2383F3D2E160056295CC7B5275C6"
    "697FB23B021D8F09CD25C3C82CDF071E58886C91A0C473166BA301930781626053615984B5"
    "6EE5FCDEC2F78587104EF0069603F575F12564394284773CF0BF88900537536D5610712344"
    "1BAD7AAB5867BCCF758CD44637215F430F7BDF9FA8F30B9069F70BCA83D6921061E29CD7BF"
    "5D182CF259D7C39E2AB95511417DBCBFED99035584A904E5DFFCE1202307C72616B76464FD"
    "66D755F13899C06D8071E5EC9847D099A0FE0274ECB0E310EE9A771AF9B7D39BC376057380"
    "52C708F3AFB3CF87C610B351F55FC47E37CDFA17512CCB6167F2EC1783BB9D30EE040A7F93"
    "C0A763ED0CF1B19BBD68E1D4C639C33FDBC678A31CDE950960276A3603381EEAA021742604"
    "31B8E2687A38501E5F59BF81D356465E45D51F4B09A2A1185F770F031B8AECB7FAFB07ADBF"
    "2AA1DB772A0B7C0D827B81646966839A45CD47E29C01A49CC324790266E8C26836F98E53BF"
    "B1EB7D5CA037948DD0CD03C60B47F2DF93B7F324B2B68464CC4F0FBE90EA3E25FF9B1599FB"
    "5C7C7592B0EAE372375FC542AE30891839E3BC6F9C247DEAD64183026F24F0DEAEB295BE17"
    "A227EDC877025F5889B84DFD9D211C92062D4EBF19171F7AF1FE16FDC691B669E027431FB5"
    "1E780297C36B2F2A6E767F6F96A869ADFAA3A2CD41F6A760731FCF115C57AAF0A3B78EAC97"
    "81C2E57EBF0C2C9D92472E5BE7654EAA4D246EF067F48A32FFF800EC6C8E0C728737309E71"
    "4C082C4414B4B1432A91E05F84862A3FF3604B30FEC555BFFBCB983B89D63B86348E59B5E7"
    "5365CBA39EA85230697BD47DD9BE18FCB484DF898BF04B34766EFA2EBA5CB026389FE871A1"
    "E5D113B934B8B7209DA8B8E37423DFEABA4B5F45305302E789B5B52A9F4E680D2F157BF9F5"
    "14C93179715CF7D9A3459F58E9CAC38646211F3E4C45B5761254B3217FE0301CC3136A8547"
    "BE077BD8ACE868C25ED3BAFB2EB4A49B2E92DC9ACC165826B03830F082715B698F355FCDF1"
    "0767EE1E17426527CD60402F1E3D920EED26DD75446B1C5A3A3557C5D731EF5464616AEA5A"
    "7B565EDD3950ABD88718FFA979987B33791C50176E89F2FEF1192B3A21F7199DD53F344A32"
    "DCCCF53F5D1FF6254326B0A5FFC89B15444DE84053D5AB221E6A586655F7F1E6C9A8B2B90B"
    "7732054361456E63129C0200000001000100020000000C0000080000000002000000000000"
    "010092B0082F981D839323B73F98D42941612C0D2B890AD3C2DCB5E94CFF8518A34E67ADD5"
    "39B7EC6E81AFD19D9408B37CA49405F62B4CA8E8B6A7F3B07E13222A0BADDDFDA90B34B31E"
    "0D8B3FFE2C44D15F9432C193E5AE17CA0BB26A341E4ECFF261C06179D95890956F4D99FB17"
    "F96C4F976AAADD39C9E5C49AEB7D169E768DBCEE3B58E7CB0CD5EA20769E24E40F791F1579"
    "1367C732EE88BAD9B4087FBCDC0A97ECE9C18BEA47763753A426E0F37E7B675CE4C9090555"
    "AF49B9ED8121252811A193AA57964C200920559A7041EEF758C67BCAFC1CAD3A33F8394E79"
    "C65143FF1DCB517BB74107E4FAA6BC21291B3D61F903F155635E91E9DC2142B7C510902F1A"
    "CB020A8002804F4EDE62D4AA8C8E614DF4D2760CEF44E9CCFF7F727C9EC8570481D2495566"
    "0287D2AC32CAAEECAFE90E32E9BB7CEEB1D80449A024AEE98C0094818119FD553C7CC8ED17"
    "6DB25F546B8B466B019C821497748FBA6AE8F3ED00FCA09EBA21567601BA2D83C69A97137F"
    "5B3A94542BDA21ED174ED3159E7C4847326E7A17AD2E109C9C5C44D8A94DF94F7B0DEDD3DB"
    "6F86A5EF427F43EE29A023EB6463E4F918D9E9715AD71148A7E05CCA2F03DE7FE65AB5FB93"
    "77249A24CF9B574BF6C3424C733CA8F17B892095245FEBE0036F4BB1C24F8766F90147F95A"
    "18057545751E0040007FDCCB121B00F881293C521C4F3BCEB9C1389A288CCE92CD386BB5AD"
    "6FCE12300101000051554F54531C585D525B83CD901717617DC2A06CE30B0B0A0000000000"
    "0000000000000000000000000000001A14865AEDD337518E56F648440B81B4CBD9359FDFF3"
    "22E0020A80024A2149D502C25B05955C2E6116BE7526F1D6691D4B18EA499E0A3D669E817E"
    "38AA0FE1ADB80E7466D1739506F79FEB883C024396EA8D9A0B939AF61D6EFB080A344DDA79"
    "2D9F416C88DC63792244658A912CC4D7CA343819CCF079A701BCC26F9A5F25BDC09DD4ECCB"
    "194914A9E130B32E873BE49C103EC235FA70C7BEB4B827DC41D807BB7E716F2FEA7940F2D3"
    "70C87335A967A5216F7692EAC7071C3FBA380179377A36F4C36CBC2FA14AE04C969F083F27"
    "3E0D6B91DF29667FCDA2D64A05D95DC53D5FDFC552DA98C46D586482895D95B6F39F7366FC"
    "02B8E3E7A2A54B671A9C94212836811964D26EE0C78723A2609D0A27BF727A6C5768CFA14C"
    "E38CF812300101000051554F54E65F9ABC7607AD60DD8ECD35D156508CD7FA8E1100000000"
    "000000000000000000000000000000001A140B17BFBBACD56AE2BFCCCEEFCDA05582B492AC"
    "7922134348454C4C20544553542036323937204445562A20F2526B31A6C612D67D0BD0A950"
    "E5E2AA7AD0C88453E2CA5CCA68171E8A09DF573001";

}  // namespace

class PcaEnrollV1Test : public testing::Test {
 public:
  PcaEnrollV1Test() {
    SetupEnrollRequestToVerify();
    pca_enroll_ = std::make_unique<fake_pca_agent::PcaEnrollV1>(request_);
  }
  ~PcaEnrollV1Test() override = default;

 protected:
  attestation::AttestationEnrollmentRequest request_;
  std::unique_ptr<fake_pca_agent::PcaEnrollV1> pca_enroll_;

  void SetupEnrollRequestToVerify() {
    std::vector<uint8_t> output;
    ASSERT_TRUE(base::HexStringToBytes(kEnrollRequestInHex, &output));
    ASSERT_TRUE(
        request_.ParseFromString(std::string(output.begin(), output.end())));
  }
};

TEST_F(PcaEnrollV1Test, Enroll) {
  EXPECT_TRUE(pca_enroll_->Preprocess());
  EXPECT_TRUE(pca_enroll_->Verify());
  EXPECT_TRUE(pca_enroll_->Generate());
}

}  // namespace hwsec_test_utils
