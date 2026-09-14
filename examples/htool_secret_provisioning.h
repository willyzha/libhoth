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

#ifndef LIBHOTH_EXAMPLES_HTOOL_SECRET_PROVISIONING_H_
#define LIBHOTH_EXAMPLES_HTOOL_SECRET_PROVISIONING_H_

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

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_SECRET_PROVISIONING_H_
