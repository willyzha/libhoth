// Copyright 2025 Google LLC
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
#ifndef LIBHOTH_EXAMPLES_HTOOL_PROVISIONING_H_
#define LIBHOTH_EXAMPLES_HTOOL_PROVISIONING_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "htool_dice_certs.h"
#include "htool_security_v2_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct htool_invocation;

#define PROVISIONING_KEY_IDENTIFIER_SIZE 4

// Header of the RoT's provisioning encryption key certificate.
struct provisioning_encryption_key_certificate_header {
  uint32_t signature_version;
  // Four character code identifying the key.
  uint8_t key_identifier[PROVISIONING_KEY_IDENTIFIER_SIZE];
  uint32_t key_size;
  uint32_t key_type;
  uint32_t key_op;
} __attribute__((packed));

// The RoT's provisioning encryption key certificate (148 bytes).
struct provisioning_encryption_key_certificate {
  struct provisioning_encryption_key_certificate_header header;
  struct ec_p256_public_key public_key;
  struct ec_p256_signature signature;
} __attribute__((packed));

// Response to the "get encryption key" command (724 bytes): the encryption key
// certificate plus the DICE chain that endorses it.
struct provisioning_encryption_key_certificate_chain {
  struct provisioning_encryption_key_certificate encryption_key_cert;
  struct dice_certificate_chain dice_certificate_chain;
} __attribute__((packed));

// Writes the certificate chain in a human-readable form.
void htool_print_provisioning_encryption_key_certificate_chain(
    FILE* out,
    const struct provisioning_encryption_key_certificate_chain* chain);

// Retrieves the provisioning encryption key certificate chain.
int htool_provisioning_get_encryption_key(const struct htool_invocation* inv);

// Loads secrets that were encrypted to the provisioning encryption key.
int htool_provisioning_store_secrets(const struct htool_invocation* inv);

#define PROVISIONING_LOG_MAX_SIZE 6144

#define PROVISIONING_LOG_CHUNK_MAX_SIZE 1008

#define PROVISIONING_CERT_MAX_SIZE 240

struct hoth_provisioning_log_header {
  uint8_t version;  // 1
  uint8_t reserved;
  uint16_t size;      // size of the log content
  uint32_t checksum;  // CRC32 checksum of |size| bytes of log data
} __attribute__((packed));

struct hoth_provisioning_log_request {
  uint8_t version;    // 1
  uint8_t operation;  // enum provisioning_log_op
  uint16_t reserved;
  uint16_t offset;    // Chunked read/write offset
  uint16_t size;      // Chunked read/write size
  uint32_t checksum;  // CRC32 checksum of the full provisioning log
} __attribute__((packed));

struct hoth_provisioning_log {
  struct hoth_provisioning_log_header hdr;
  uint8_t data[PROVISIONING_LOG_CHUNK_MAX_SIZE];
} __attribute__((packed));

#define PROVISIONING_LOG_WRITE_CHUNK_MAX_SIZE 1004

#define PROVISIONING_DEVICE_ID_SIZE 32

enum provisioning_log_op {
  PROVISIONING_LOG_READ = 0,
  PROVISIONING_LOG_WRITE = 1,
  PROVISIONING_LOG_COMMIT = 2,
  PROVISIONING_LOG_VALIDATE_AND_SIGN = 3,
  PROVISIONING_LOG_ACTIVATE = 4,
};

// This is a standalone CRC32 that matches Titan Firmware.
// A table-free bit-level implementation is okay since there are no
// performance constraints in it's use in htool_validate_and_sign.
uint32_t crc32(uint32_t initial_value, const uint8_t* buf, size_t size);

// Retrieve the provisioning log from the device.
int htool_get_provisioning_log(const struct htool_invocation* inv);

// Validate and Sign the provisioning log.
int htool_validate_and_sign(const struct htool_invocation* inv);

// Writes and commits the provisioning log.
int htool_provisioning_write(const struct htool_invocation* inv);

// Activates the provisioning log with the provided Device ID.
int htool_provisioning_activate(const struct htool_invocation* inv);

// Loads the ML-DSA-44 public key to the RoT.
int htool_provisioning_load_mldsa_key(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_PROVISIONING_H_
