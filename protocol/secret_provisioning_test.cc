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

#include "protocol/secret_provisioning.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "protocol/host_cmd.h"
#include "test/libhoth_device_mock.h"

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

constexpr uint16_t kCommand =
    HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_SECRET_PROVISIONING;

// Returns the request header that was serialized into a host command.
hoth_secret_provisioning_request_header HeaderOf(const void* request) {
  hoth_secret_provisioning_request_header header;
  std::memcpy(
      &header,
      static_cast<const uint8_t*>(request) + sizeof(struct hoth_host_request),
      sizeof(header));
  return header;
}

TEST_F(LibHothTest, GetEncryptionKeySuccess) {
  // The response layout is firmware-specific, so the protocol layer just
  // passes the bytes through.
  std::vector<uint8_t> expected_response(724);
  for (size_t i = 0; i < expected_response.size(); ++i) {
    expected_response[i] = static_cast<uint8_t>(i);
  }

  EXPECT_CALL(mock_, send(_, UsesCommand(kCommand), _))
      .WillOnce([](struct libhoth_device*, const void* request, size_t) {
        const hoth_secret_provisioning_request_header header =
            HeaderOf(request);
        EXPECT_EQ(header.version, HOTH_SECRET_PROVISIONING_REQUEST_VERSION);
        EXPECT_EQ(header.command, HOTH_SECRET_PROVISIONING_GET_ENCRYPTION_KEY);
        EXPECT_EQ(header.size, sizeof(hoth_secret_provisioning_request_header));
        return LIBHOTH_OK;
      });
  EXPECT_CALL(mock_, receive)
      .WillOnce(
          DoAll(CopyResp(expected_response.data(), expected_response.size()),
                Return(LIBHOTH_OK)));

  std::vector<uint8_t> response(expected_response.size());
  size_t response_size = 0;
  EXPECT_EQ(libhoth_secret_provisioning_get_encryption_key(
                &hoth_dev_, response.data(), response.size(), &response_size),
            HOTH_SUCCESS);
  EXPECT_EQ(response_size, expected_response.size());
  EXPECT_EQ(response, expected_response);
}

TEST_F(LibHothTest, GetEncryptionKeyNullParams) {
  size_t response_size = 0;
  uint8_t response[4] = {};
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(libhoth_secret_provisioning_get_encryption_key(
                &hoth_dev_, nullptr, sizeof(response), &response_size)),
            LIBHOTH_ERR_INVALID_PARAMETER);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(libhoth_secret_provisioning_get_encryption_key(
                &hoth_dev_, response, sizeof(response), nullptr)),
            LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibHothTest, StoreSecretsSuccess) {
  const std::vector<uint8_t> secrets = {0xde, 0xad, 0xbe, 0xef, 0x01};

  EXPECT_CALL(mock_, send(_, UsesCommand(kCommand), _))
      .WillOnce([&secrets](struct libhoth_device*, const void* request,
                           size_t request_size) {
        const hoth_secret_provisioning_request_header header =
            HeaderOf(request);
        EXPECT_EQ(header.version, HOTH_SECRET_PROVISIONING_REQUEST_VERSION);
        EXPECT_EQ(header.command, HOTH_SECRET_PROVISIONING_STORE_SECRETS);
        // The size field covers the header and the encrypted secret.
        EXPECT_EQ(header.size, sizeof(hoth_secret_provisioning_request_header) +
                                   secrets.size());
        EXPECT_EQ(request_size,
                  sizeof(struct hoth_host_request) +
                      sizeof(hoth_secret_provisioning_request_header) +
                      secrets.size());
        const uint8_t* payload =
            static_cast<const uint8_t*>(request) +
            sizeof(struct hoth_host_request) +
            sizeof(hoth_secret_provisioning_request_header);
        EXPECT_EQ(std::memcmp(payload, secrets.data(), secrets.size()), 0);
        return LIBHOTH_OK;
      });
  uint32_t dummy = 0;
  EXPECT_CALL(mock_, receive)
      .WillOnce(DoAll(CopyResp(&dummy, 0), Return(LIBHOTH_OK)));

  EXPECT_EQ(libhoth_secret_provisioning_store_secrets(
                &hoth_dev_, secrets.data(), secrets.size()),
            HOTH_SUCCESS);
}

TEST_F(LibHothTest, StoreSecretsRejectsInvalidSizes) {
  const std::vector<uint8_t> secrets(16, 0xa5);

  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(libhoth_secret_provisioning_store_secrets(
                &hoth_dev_, secrets.data(), 0)),
            LIBHOTH_ERR_INVALID_PARAMETER);
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(libhoth_secret_provisioning_store_secrets(
                &hoth_dev_, nullptr, secrets.size())),
            LIBHOTH_ERR_INVALID_PARAMETER);
  // Anything that does not fit in the mailbox must be rejected up front rather
  // than silently truncated.
  EXPECT_EQ(LIBHOTH_ERR_GET_CODE(libhoth_secret_provisioning_store_secrets(
                &hoth_dev_, secrets.data(),
                HOTH_SECRET_PROVISIONING_MAX_SECRETS_SIZE + 1)),
            LIBHOTH_ERR_INVALID_PARAMETER);
}

}  // namespace
