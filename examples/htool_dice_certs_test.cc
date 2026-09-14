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

#include "examples/htool_dice_certs.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <numeric>
#include <string>
#include <vector>

namespace {

// The firmware serializes these structures directly into the host command
// response, so their layout must not drift.
static_assert(sizeof(struct keycert_header) == 64, "");
static_assert(sizeof(struct device_id_keycert_header) == 64, "");
static_assert(sizeof(struct alias_key_certificate) == 192, "");
static_assert(sizeof(struct alias_key_certificate_v1) == 224, "");
static_assert(sizeof(struct device_id_certificate) == 192, "");
static_assert(sizeof(struct device_id_endorsement_certificate) == 160, "");
static_assert(sizeof(struct dice_certificate_chain) == 576, "");

static_assert(offsetof(struct keycert_header, hw_id) == 32, "");
static_assert(offsetof(struct keycert_header, bootloader_tag) == 44, "");
static_assert(offsetof(struct keycert_header, reserved_1) == 56, "");
static_assert(offsetof(struct device_id_keycert_header, endorsement_key_id) ==
                  32,
              "");
static_assert(offsetof(struct device_id_keycert_header, hw_id) == 48, "");
static_assert(offsetof(struct device_id_keycert_header, bootloader_tag) == 60,
              "");
static_assert(offsetof(struct dice_certificate_chain, device_id_certificate) ==
                  224,
              "");
static_assert(offsetof(struct dice_certificate_chain,
                       device_id_endorsement_certificate) == 416,
              "");

// Captures everything a printer writes to its output stream.
std::string Capture(const std::function<void(FILE*)>& printer) {
  char* buf = nullptr;
  size_t size = 0;
  FILE* out = open_memstream(&buf, &size);
  EXPECT_NE(out, nullptr);
  printer(out);
  fclose(out);
  std::string result(buf, size);
  free(buf);
  return result;
}

TEST(HtoolDiceCerts, PrintHexString) {
  const uint8_t data[] = {0x00, 0x0f, 0xa5, 0xff};
  EXPECT_EQ(Capture([&](FILE* out) {
              htool_print_hex_string(out, data, sizeof(data));
            }),
            "000fa5ff");
}

TEST(HtoolDiceCerts, PrintHexFieldIsIndented) {
  const uint8_t data[] = {0x41, 0x00, 0xff};
  EXPECT_EQ(Capture([&](FILE* out) {
              htool_print_hex_field(out, 2, "key_info", data, sizeof(data));
            }),
            "  key_info: 4100ff\n");
}

TEST(HtoolDiceCerts, PrintPublicKeyAndSignature) {
  struct ec_p256_public_key key = {};
  key.q_a_x[0] = 0x01;
  key.q_a_y[31] = 0x02;
  const std::string key_text = Capture([&](FILE* out) {
    htool_print_ec_p256_public_key(out, 0, "public_key", &key);
  });
  EXPECT_THAT(key_text, testing::StartsWith("public_key:\n  q_a_x: 01"));
  EXPECT_THAT(key_text, testing::EndsWith("02\n"));

  struct ec_p256_signature signature = {};
  signature.r[0] = 0xaa;
  signature.s[0] = 0xbb;
  const std::string sig_text = Capture([&](FILE* out) {
    htool_print_ec_p256_signature(out, 0, "signature", &signature);
  });
  EXPECT_THAT(sig_text, testing::HasSubstr("  r: aa"));
  EXPECT_THAT(sig_text, testing::HasSubstr("  s: bb"));
}

TEST(HtoolDiceCerts, PrintKeycertHeader) {
  struct keycert_header header = {};
  header.signature_version = 1;
  header.signature_purpose = 7;
  header.extension_header_type = 2;
  header.key_type = 3;
  header.key_op = 4;
  header.key_alg = 5;
  header.hw_id = 0x0011223344556677ULL;
  header.hw_cat = 9;
  header.bootloader_tag = 0xdeadbeef;
  header.fw_epoch = 42;
  header.fw_major_version = 11;
  header.pub_key_size = 64;

  const std::string text = Capture([&](FILE* out) {
    htool_print_keycert_header(out, 0, "header", &header);
  });

  EXPECT_THAT(text, testing::HasSubstr("signature_version: 1\n"));
  EXPECT_THAT(text, testing::HasSubstr("signature_purpose: 7\n"));
  EXPECT_THAT(text, testing::HasSubstr("extension_header_type: 2\n"));
  EXPECT_THAT(text, testing::HasSubstr("key_type: 3\n"));
  EXPECT_THAT(text, testing::HasSubstr("key_op: 4\n"));
  EXPECT_THAT(text, testing::HasSubstr("key_alg: 5\n"));
  // Hardware identifiers are easier to cross-reference in hex.
  EXPECT_THAT(text, testing::HasSubstr("hw_id: 0x0011223344556677\n"));
  EXPECT_THAT(text, testing::HasSubstr("hw_cat: 9\n"));
  EXPECT_THAT(text, testing::HasSubstr("bootloader_tag: 0xdeadbeef\n"));
  EXPECT_THAT(text, testing::HasSubstr("fw_epoch: 42\n"));
  EXPECT_THAT(text, testing::HasSubstr("fw_major_version: 11\n"));
  EXPECT_THAT(text, testing::HasSubstr("pub_key_size: 64\n"));
}

TEST(HtoolDiceCerts, AliasKeyCertificateOmitsFwHashWhenNotProvided) {
  struct alias_key_certificate cert = {};
  const std::string text = Capture([&](FILE* out) {
    htool_print_alias_key_certificate(out, 0, "alias_key_certificate", &cert,
                                      nullptr);
  });
  EXPECT_THAT(text, testing::Not(testing::HasSubstr("fw_hash")));

  uint8_t fw_hash[KEYCERT_FW_HASH_SIZE] = {};
  fw_hash[0] = 0x5a;
  const std::string text_with_hash = Capture([&](FILE* out) {
    htool_print_alias_key_certificate(out, 0, "alias_key_certificate", &cert,
                                      fw_hash);
  });
  EXPECT_THAT(text_with_hash, testing::HasSubstr("fw_hash: 5a"));
}

TEST(HtoolDiceCerts, PrintDiceCertificateChain) {
  // Fill the chain with a byte pattern so that mis-ordered fields would show
  // up as differences in the rendered output.
  std::vector<uint8_t> raw(sizeof(struct dice_certificate_chain));
  std::iota(raw.begin(), raw.end(), 0);
  struct dice_certificate_chain chain;
  memcpy(&chain, raw.data(), raw.size());

  const std::string text = Capture([&](FILE* out) {
    htool_print_dice_certificate_chain(out, 0, "DICE Certificate Chain",
                                       &chain);
  });

  EXPECT_THAT(text, testing::StartsWith("DICE Certificate Chain:\n"));
  EXPECT_THAT(text, testing::HasSubstr("alias_key_certificate:"));
  EXPECT_THAT(text, testing::HasSubstr("device_id_certificate:"));
  EXPECT_THAT(text, testing::HasSubstr("device_id_endorsement_certificate:"));
  // The alias key certificate in the chain always carries a firmware hash.
  EXPECT_THAT(text, testing::HasSubstr("fw_hash: "));
  // Only the device ID certificate header has an endorsement_key_id field.
  EXPECT_EQ(text.find("endorsement_key_id"), text.rfind("endorsement_key_id"));
}

}  // namespace
