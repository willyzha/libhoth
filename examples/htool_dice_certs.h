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

// Layout of the DICE certificates reported by RoT firmware, and helpers to
// print them in a human-readable form.
//
// Tools that need to verify or sign these certificates should consume the raw
// certificate bytes rather than the rendering produced here, which is intended
// for operators inspecting a device.

#ifndef LIBHOTH_EXAMPLES_HTOOL_DICE_CERTS_H_
#define LIBHOTH_EXAMPLES_HTOOL_DICE_CERTS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "htool_security_v2_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEYCERT_KEY_INFO_SIZE 4
#define KEYCERT_CERT_VALIDITY_SIZE 16
#define KEYCERT_ENDORSEMENT_KEY_ID_SIZE 16
#define KEYCERT_FW_HASH_SIZE 32
#define KEYCERT_DEVICE_ID_CERT_HASH_SIZE 32

// Header prefixed to most key certificates and certificate signing requests.
// All multi-byte fields are little-endian.
struct keycert_header {
  uint32_t signature_version;
  uint32_t signature_purpose;
  uint8_t extension_header_type;
  uint8_t key_type;
  uint8_t key_op;
  uint8_t key_alg;
  uint8_t key_info[KEYCERT_KEY_INFO_SIZE];
  uint8_t cert_validity[KEYCERT_CERT_VALIDITY_SIZE];
  uint64_t hw_id;
  uint16_t hw_cat;
  uint8_t reserved_0[2];
  uint32_t bootloader_tag;
  uint32_t fw_epoch;
  uint16_t fw_major_version;
  uint16_t pub_key_size;
  uint8_t reserved_1[8];
} __attribute__((packed));

// Header of the device ID certificate. It identifies the key that endorsed the
// device ID in place of the epoch/version fields of `struct keycert_header`.
struct device_id_keycert_header {
  uint32_t signature_version;
  uint32_t signature_purpose;
  uint8_t extension_header_type;
  uint8_t key_type;
  uint8_t key_op;
  uint8_t key_alg;
  uint8_t key_info[KEYCERT_KEY_INFO_SIZE];
  uint8_t cert_validity[KEYCERT_CERT_VALIDITY_SIZE];
  uint8_t endorsement_key_id[KEYCERT_ENDORSEMENT_KEY_ID_SIZE];
  uint64_t hw_id;
  uint16_t hw_cat;
  uint16_t signed_data_size;
  uint32_t bootloader_tag;
} __attribute__((packed));

// DICE alias key certificate without the trailing firmware hash (192 bytes).
struct alias_key_certificate {
  struct keycert_header header;
  struct ec_p256_public_key public_key;
  struct ec_p256_signature signature;
} __attribute__((packed));

// DICE alias key certificate including the firmware hash it attests to
// (224 bytes).
struct alias_key_certificate_v1 {
  struct alias_key_certificate cert;
  uint8_t fw_hash[KEYCERT_FW_HASH_SIZE];
} __attribute__((packed));

// Device ID certificate signed during provisioning (192 bytes).
struct device_id_certificate {
  struct device_id_keycert_header header;
  struct ec_p256_public_key key;
  struct ec_p256_signature signature;
} __attribute__((packed));

// Endorsement of the device ID certificate by the provisioning station's RW
// key (160 bytes).
struct device_id_endorsement_certificate {
  uint8_t device_id_cert_hash[KEYCERT_DEVICE_ID_CERT_HASH_SIZE];
  struct ec_p256_public_key endorsement_rw_key;
  struct ec_p256_signature signature;
} __attribute__((packed));

// The full DICE certificate chain reported by the RoT (576 bytes).
struct dice_certificate_chain {
  struct alias_key_certificate_v1 alias_key_certificate;
  struct device_id_certificate device_id_certificate;
  struct device_id_endorsement_certificate device_id_endorsement_certificate;
} __attribute__((packed));

// Writes `size` bytes as a lowercase, contiguous hex string, without
// separators or a trailing newline.
void htool_print_hex_string(FILE* out, const uint8_t* data, size_t size);

// Writes `name: <hex>`, indented by `indent` spaces.
void htool_print_hex_field(FILE* out, int indent, const char* name,
                           const uint8_t* data, size_t size);

// Writes an EC P256 public key, indented by `indent` spaces.
void htool_print_ec_p256_public_key(FILE* out, int indent, const char* name,
                                    const struct ec_p256_public_key* key);

// Writes an EC P256 signature, indented by `indent` spaces.
void htool_print_ec_p256_signature(FILE* out, int indent, const char* name,
                                   const struct ec_p256_signature* signature);

// Writes a `struct keycert_header`, indented by `indent` spaces.
void htool_print_keycert_header(FILE* out, int indent, const char* name,
                                const struct keycert_header* header);

// Writes the alias key certificate. The firmware hash is only printed when
// `fw_hash` is non-NULL.
void htool_print_alias_key_certificate(FILE* out, int indent, const char* name,
                                       const struct alias_key_certificate* cert,
                                       const uint8_t* fw_hash);

// Writes the device ID certificate.
void htool_print_device_id_certificate(
    FILE* out, int indent, const char* name,
    const struct device_id_certificate* cert);

// Writes the endorsement of the device ID certificate.
void htool_print_device_id_endorsement_certificate(
    FILE* out, int indent, const char* name,
    const struct device_id_endorsement_certificate* cert);

// Writes the full DICE certificate chain.
void htool_print_dice_certificate_chain(
    FILE* out, int indent, const char* name,
    const struct dice_certificate_chain* chain);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_DICE_CERTS_H_
