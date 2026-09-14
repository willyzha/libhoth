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

// Host command used to provision secrets into a RoT during manufacturing.
//
// The RoT owns an encryption key whose certificate chain is retrieved with
// GET_ENCRYPTION_KEY. Secrets are encrypted to that key offline and then
// handed back to the RoT with STORE_SECRETS, so plaintext secrets never
// traverse the host.

#ifndef LIBHOTH_PROTOCOL_SECRET_PROVISIONING_H_
#define LIBHOTH_PROTOCOL_SECRET_PROVISIONING_H_

#include <stddef.h>
#include <stdint.h>

#include "protocol/host_cmd.h"
#include "protocol/status.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_PRV_CMD_HOTH_SECRET_PROVISIONING 0x0043

#define HOTH_SECRET_PROVISIONING_REQUEST_VERSION 1

enum hoth_secret_provisioning_command {
  // Returns the encryption key certificate along with the DICE certificate
  // chain that endorses it.
  HOTH_SECRET_PROVISIONING_GET_ENCRYPTION_KEY = 0,
  // Decrypts and persists secrets that were encrypted to the encryption key.
  HOTH_SECRET_PROVISIONING_STORE_SECRETS = 1,
  // Loads the ML-DSA public key used to verify provisioning payloads.
  HOTH_SECRET_PROVISIONING_LOAD_MLDSA_PUBLIC_KEY = 2,
};

struct hoth_secret_provisioning_request_header {
  // Must be HOTH_SECRET_PROVISIONING_REQUEST_VERSION.
  uint8_t version;
  // One of enum hoth_secret_provisioning_command.
  uint8_t command;
  // Size of this header plus any argument bytes that follow it.
  uint16_t size;
} __attribute__((packed));

// Largest secret blob that fits in a single host command request.
#define HOTH_SECRET_PROVISIONING_MAX_SECRETS_SIZE            \
  (LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_request) - \
   sizeof(struct hoth_secret_provisioning_request_header))

// Retrieves the encryption key certificate chain. Its layout depends on the
// RoT firmware, so the caller supplies the buffer to decode and receives the
// number of bytes the RoT returned in `out_response_size`.
libhoth_error libhoth_secret_provisioning_get_encryption_key(
    struct libhoth_device* dev, void* response, size_t response_size,
    size_t* out_response_size);

// Stores `secrets_size` bytes of encrypted secrets. The blob must have been
// encrypted to the public key reported by
// libhoth_secret_provisioning_get_encryption_key().
libhoth_error libhoth_secret_provisioning_store_secrets(
    struct libhoth_device* dev, const void* secrets, size_t secrets_size);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_PROTOCOL_SECRET_PROVISIONING_H_
