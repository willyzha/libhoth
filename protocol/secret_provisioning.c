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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "protocol/host_cmd.h"
#include "protocol/status.h"
#include "transports/libhoth_device.h"

libhoth_error libhoth_secret_provisioning_get_encryption_key(
    struct libhoth_device* dev, void* response, size_t response_size,
    size_t* out_response_size) {
  if (dev == NULL || response == NULL || out_response_size == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  const struct hoth_secret_provisioning_request_header request = {
      .version = HOTH_SECRET_PROVISIONING_REQUEST_VERSION,
      .command = HOTH_SECRET_PROVISIONING_GET_ENCRYPTION_KEY,
      .size = sizeof(struct hoth_secret_provisioning_request_header),
  };

  return libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_SECRET_PROVISIONING,
      /*version=*/0, &request, sizeof(request), response, response_size,
      out_response_size);
}

libhoth_error libhoth_secret_provisioning_store_secrets(
    struct libhoth_device* dev, const void* secrets, size_t secrets_size) {
  if (dev == NULL || secrets == NULL || secrets_size == 0 ||
      secrets_size > HOTH_SECRET_PROVISIONING_MAX_SECRETS_SIZE) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  uint8_t request[sizeof(struct hoth_secret_provisioning_request_header) +
                  HOTH_SECRET_PROVISIONING_MAX_SECRETS_SIZE];
  const size_t request_size =
      sizeof(struct hoth_secret_provisioning_request_header) + secrets_size;

  const struct hoth_secret_provisioning_request_header header = {
      .version = HOTH_SECRET_PROVISIONING_REQUEST_VERSION,
      .command = HOTH_SECRET_PROVISIONING_STORE_SECRETS,
      .size = (uint16_t)request_size,
  };
  memcpy(request, &header, sizeof(header));
  memcpy(request + sizeof(header), secrets, secrets_size);

  size_t response_size = 0;
  return libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_SECRET_PROVISIONING,
      /*version=*/0, request, request_size, NULL, 0, &response_size);
}

libhoth_error libhoth_secret_provisioning_load_mldsa_public_key(
    struct libhoth_device* dev, const void* key, size_t key_size) {
  if (dev == NULL || key == NULL ||
      key_size != HOTH_SECRET_PROVISIONING_MLDSA44_PUBLIC_KEY_BYTES) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  const uint8_t* key_bytes = (const uint8_t*)key;
  uint16_t offset = 0;
  while (offset < key_size) {
    uint16_t chunk_size = (uint16_t)(key_size - offset);
    if (chunk_size > HOTH_SECRET_PROVISIONING_LOAD_KEY_CHUNK_MAX_SIZE) {
      chunk_size = HOTH_SECRET_PROVISIONING_LOAD_KEY_CHUNK_MAX_SIZE;
    }

    uint8_t request[sizeof(struct hoth_secret_provisioning_request_header) +
                    sizeof(struct hoth_secret_provisioning_load_key_args) +
                    HOTH_SECRET_PROVISIONING_LOAD_KEY_CHUNK_MAX_SIZE];
    const size_t req_size =
        sizeof(struct hoth_secret_provisioning_request_header) +
        sizeof(struct hoth_secret_provisioning_load_key_args) + chunk_size;

    const struct hoth_secret_provisioning_request_header header = {
        .version = HOTH_SECRET_PROVISIONING_REQUEST_VERSION,
        .command = HOTH_SECRET_PROVISIONING_LOAD_MLDSA_PUBLIC_KEY,
        .size = (uint16_t)req_size,
    };
    const struct hoth_secret_provisioning_load_key_args args = {
        .offset = offset,
        .size = chunk_size,
    };

    uint8_t* p = request;
    memcpy(p, &header, sizeof(header));
    p += sizeof(header);
    memcpy(p, &args, sizeof(args));
    p += sizeof(args);
    memcpy(p, key_bytes + offset, chunk_size);

    size_t response_size = 0;
    libhoth_error err = libhoth_hostcmd_exec_v2(
        dev,
        HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_SECRET_PROVISIONING,
        /*version=*/0, request, req_size, NULL, 0, &response_size);
    if (err != HOTH_SUCCESS) {
      return err;
    }

    offset += chunk_size;
  }

  return HOTH_SUCCESS;
}
