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

#include "protocol/util.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace {

TEST(ParseHexString, DecodesBothCases) {
  uint8_t out[4] = {};
  size_t out_len = 0;
  EXPECT_EQ(libhoth_parse_hex_string("00FfaB10", out, sizeof(out), &out_len),
            0);
  EXPECT_EQ(out_len, 4u);
  EXPECT_EQ(std::vector<uint8_t>(out, out + out_len),
            (std::vector<uint8_t>{0x00, 0xff, 0xab, 0x10}));
}

TEST(ParseHexString, AcceptsOutputBufferLargerThanInput) {
  uint8_t out[8] = {};
  size_t out_len = 0;
  EXPECT_EQ(libhoth_parse_hex_string("a5", out, sizeof(out), &out_len), 0);
  EXPECT_EQ(out_len, 1u);
  EXPECT_EQ(out[0], 0xa5);
}

TEST(ParseHexString, RejectsMalformedInput) {
  uint8_t out[4] = {};
  size_t out_len = 0;
  // Empty strings carry no data.
  EXPECT_EQ(libhoth_parse_hex_string("", out, sizeof(out), &out_len), -1);
  // Odd digit counts are ambiguous.
  EXPECT_EQ(libhoth_parse_hex_string("abc", out, sizeof(out), &out_len), -1);
  // Non-hex characters, including the "0x" prefix and separators.
  EXPECT_EQ(libhoth_parse_hex_string("0xab", out, sizeof(out), &out_len), -1);
  EXPECT_EQ(libhoth_parse_hex_string("ab cd", out, sizeof(out), &out_len), -1);
  EXPECT_EQ(libhoth_parse_hex_string("zz", out, sizeof(out), &out_len), -1);
  // Truncating the caller's data would be worse than failing.
  EXPECT_EQ(libhoth_parse_hex_string("0011223344", out, sizeof(out), &out_len),
            -1);
  EXPECT_EQ(libhoth_parse_hex_string(nullptr, out, sizeof(out), &out_len), -1);
}

}  // namespace
