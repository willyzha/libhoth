// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "examples/htool_attestation_key.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "examples/test/test_util.h"
#include "htool_security_v2.h"
#include "htool_security_version.h"

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

}  // namespace

// Mock for htool_invocation
static HtoolInvocationMock* g_htool_invocation_mock = nullptr;

extern "C" int htool_get_param_string(const struct htool_invocation* inv,
                                      const char* name, const char** value) {
  if (g_htool_invocation_mock) {
    return g_htool_invocation_mock->GetParamString(name, value);
  }
  return -1;
}

extern "C" int htool_get_param_u32(const struct htool_invocation* inv,
                                   const char* name, uint32_t* value) {
  if (g_htool_invocation_mock) {
    return g_htool_invocation_mock->GetParamU32(name, value);
  }
  return -1;
}

// Mocking htool_libhoth_device
static struct libhoth_device* mock_dev = nullptr;
struct libhoth_device* htool_libhoth_device() { return mock_dev; }

// Mocking htool_get_security_version
libhoth_security_version htool_get_security_version(
    struct libhoth_device* dev) {
  return LIBHOTH_SECURITY_V2;
}

// Mock for htool_exec_security_v2_cmd
static HtoolSecurityV2Mock* g_htool_security_v2_mock = nullptr;
extern "C" int htool_exec_security_v2_cmd(
    struct libhoth_device* dev, uint8_t major, uint8_t minor,
    uint16_t base_command, struct security_v2_buffer* request_buffer,
    const struct security_v2_param* request_params,
    uint16_t request_param_count, struct security_v2_buffer* response_buffer,
    struct security_v2_param* response_params, uint16_t response_param_count) {
  if (g_htool_security_v2_mock) {
    return g_htool_security_v2_mock->htool_exec_security_v2_cmd(
        dev, major, minor, base_command, request_buffer, request_params,
        request_param_count, response_buffer, response_params,
        response_param_count);
  }
  return -1;
}

namespace {

// Fills the response params of a generate command with `csr` and `key`.
ACTION_P2(SetGenerateResponse, csr, key) {
  struct security_v2_param* response_params =
      (struct security_v2_param*)std::get<8>(args);
  std::memcpy(response_params[0].data, &csr, sizeof(csr));
  std::memcpy(response_params[1].data, &key, sizeof(key));
}

// Returns a hex string of `size` bytes whose value at index i is i.
std::string CountingHex(size_t size) {
  static const char kDigits[] = "0123456789abcdef";
  std::string hex;
  for (size_t i = 0; i < size; ++i) {
    const uint8_t byte = static_cast<uint8_t>(i);
    hex.push_back(kDigits[byte >> 4]);
    hex.push_back(kDigits[byte & 0xf]);
  }
  return hex;
}

class HtoolAttestationKeyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    mock_dev = &dummy_dev_;
    g_htool_invocation_mock = &invocation_mock_;
    g_htool_security_v2_mock = &security_v2_mock_;
  }

  void TearDown() override {
    mock_dev = nullptr;
    g_htool_invocation_mock = nullptr;
    g_htool_security_v2_mock = nullptr;
  }

  // Makes the named string parameter resolve to `value`.
  void ExpectStringParam(const std::string& name, const char* value) {
    EXPECT_CALL(invocation_mock_, GetParamString(name, _))
        .WillOnce(DoAll(SetArgPointee<1>(value), Return(0)));
  }

  struct libhoth_device dummy_dev_ = {};
  HtoolInvocationMock invocation_mock_;
  HtoolSecurityV2Mock security_v2_mock_;
};

// The wire layout is dictated by the RoT firmware, so lock in the sizes and
// field offsets that the command handlers assume.
TEST(HtoolAttestationKeyLayoutTest, StructSizes) {
  static_assert(sizeof(struct attestation_key_csr) == 256, "");
  static_assert(sizeof(struct attestation_wrapped_key) == 88, "");

  static_assert(offsetof(struct attestation_key_csr, public_key) == 64, "");
  static_assert(offsetof(struct attestation_key_csr, firmware_signature) == 128,
                "");
  static_assert(offsetof(struct attestation_key_csr, device_signature) == 192,
                "");

  static_assert(offsetof(struct attestation_wrapped_key, data_size) == 4, "");
  static_assert(offsetof(struct attestation_wrapped_key, iv) == 8, "");
  static_assert(offsetof(struct attestation_wrapped_key, hmac) == 24, "");
  static_assert(offsetof(struct attestation_wrapped_key, encrypted_data) == 56,
                "");
}

TEST_F(HtoolAttestationKeyTest, GenerateSendsCommandAndPrintsResult) {
  struct attestation_key_csr csr = {};
  csr.header.hw_id = 0x0123456789abcdef;
  struct attestation_wrapped_key key = {};
  key.wrapper_version = 1;
  key.data_size = sizeof(key.encrypted_data);

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GENERATE_ATTESTATION_KEY_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0),
          HOTH_SECURITY_V2_RESPONSE_SIZE(2) + sizeof(csr) + sizeof(key)))
      .WillOnce(DoAll(SetGenerateResponse(csr, key), Return(0)));

  // Neither output file is requested, so nothing is written to disk.
  ExpectStringParam("csr_output", "");
  ExpectStringParam("wrapped_key_output", "");

  testing::internal::CaptureStdout();
  EXPECT_EQ(htool_attestation_key_generate(nullptr), 0);
  const std::string output = testing::internal::GetCapturedStdout();

  EXPECT_THAT(output, testing::HasSubstr("Certificate Signing Request"));
  EXPECT_THAT(output, testing::HasSubstr("hw_id: 0x0123456789abcdef"));
  EXPECT_THAT(output, testing::HasSubstr("Wrapped Key"));
}

TEST_F(HtoolAttestationKeyTest, GenerateReportsCommandFailure) {
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(7));

  testing::internal::CaptureStdout();
  EXPECT_EQ(htool_attestation_key_generate(nullptr), 7);
  testing::internal::GetCapturedStdout();
}

TEST_F(HtoolAttestationKeyTest, LoadFromCsrAcceptsHexInput) {
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));
  const std::string key_hex =
      CountingHex(sizeof(struct attestation_wrapped_key));
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key_hex", _))
      .WillOnce(DoAll(SetArgPointee<1>(key_hex.c_str()), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("csr", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));
  const std::string csr_hex = CountingHex(sizeof(struct attestation_key_csr));
  EXPECT_CALL(invocation_mock_, GetParamString("csr_hex", _))
      .WillOnce(DoAll(SetArgPointee<1>(csr_hex.c_str()), Return(0)));

  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_LOAD_ATTESTATION_KEY_FROM_CSR_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(2) +
              sizeof(struct attestation_wrapped_key) +
              sizeof(struct attestation_key_csr),
          HOTH_SECURITY_V2_RESPONSE_SIZE(0)))
      .WillOnce([](struct libhoth_device*, uint8_t, uint8_t, uint16_t,
                   struct security_v2_buffer*,
                   const struct security_v2_param* request_params,
                   uint16_t request_param_count, struct security_v2_buffer*,
                   struct security_v2_param*, uint16_t) {
        // The firmware expects the wrapped key first and the signing request
        // second.
        EXPECT_EQ(request_param_count, 2);
        EXPECT_EQ(request_params[0].size,
                  sizeof(struct attestation_wrapped_key));
        EXPECT_EQ(request_params[1].size, sizeof(struct attestation_key_csr));
        const uint8_t* key =
            static_cast<const uint8_t*>(request_params[0].data);
        EXPECT_EQ(key[0], 0x00);
        EXPECT_EQ(key[1], 0x01);
        return 0;
      });

  testing::internal::CaptureStdout();
  EXPECT_EQ(htool_attestation_key_load_from_csr(nullptr), 0);
  testing::internal::GetCapturedStdout();
}

TEST_F(HtoolAttestationKeyTest, LoadFromCsrRejectsAmbiguousInput) {
  // Supplying neither a file nor a hex string is an error, and so is
  // supplying both.
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key_hex", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));
  EXPECT_EQ(htool_attestation_key_load_from_csr(nullptr), -1);

  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key", _))
      .WillOnce(DoAll(SetArgPointee<1>("/tmp/key.bin"), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key_hex", _))
      .WillOnce(DoAll(SetArgPointee<1>("00"), Return(0)));
  EXPECT_EQ(htool_attestation_key_load_from_csr(nullptr), -1);
}

TEST_F(HtoolAttestationKeyTest, LoadFromCsrRejectsWrongLengthHex) {
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key", _))
      .WillOnce(DoAll(SetArgPointee<1>(""), Return(0)));
  EXPECT_CALL(invocation_mock_, GetParamString("wrapped_key_hex", _))
      .WillOnce(DoAll(SetArgPointee<1>("0011"), Return(0)));
  EXPECT_EQ(htool_attestation_key_load_from_csr(nullptr), -1);
}

TEST_F(HtoolAttestationKeyTest, UnloadSendsCommand) {
  EXPECT_CALL(security_v2_mock_,
              htool_exec_security_v2_cmd(_, _, _, _, _, _, _, _, _, _))
      .With(IsSecurityV2Command(
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          HOTH_PRV_CMD_HOTH_SECURITY_V2_UNLOAD_ATTESTATION_KEY_MINOR_COMMAND,
          HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          HOTH_SECURITY_V2_REQUEST_SIZE(0), HOTH_SECURITY_V2_RESPONSE_SIZE(0)))
      .WillOnce(Return(0));

  testing::internal::CaptureStdout();
  EXPECT_EQ(htool_attestation_key_unload(nullptr), 0);
  EXPECT_THAT(testing::internal::GetCapturedStdout(),
              testing::HasSubstr("unloaded"));
}

}  // namespace
