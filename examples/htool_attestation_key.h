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

// Lifecycle commands for the RoT's attestation key.
//
// The RoT generates the key itself and only ever hands out the private half
// wrapped with a key it alone holds. Provisioning therefore looks like:
//
//   1. `generate` produces a certificate signing request (CSR) and the wrapped
//      private key. The CSR is sent to a CA to be signed.
//   2. `load_from_csr` installs the key using the wrapped key plus a CSR,
//      which is how a device is re-provisioned from a previously issued key.
//   3. `unload` removes the currently installed key.
//
// The certificate for a loaded key can be read back with
// `htool security get_attestation_pub_cert`.

#ifndef LIBHOTH_EXAMPLES_HTOOL_ATTESTATION_KEY_H_
#define LIBHOTH_EXAMPLES_HTOOL_ATTESTATION_KEY_H_

#include <stdint.h>
#include <stdio.h>

#include "htool_dice_certs.h"
#include "htool_security_v2_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct htool_invocation;

#define ATTESTATION_KEY_WRAPPER_IV_SIZE 16
#define ATTESTATION_KEY_WRAPPER_HMAC_SIZE 32
#define ATTESTATION_KEY_WRAPPER_DATA_SIZE 32

// A certificate signing request for a newly generated attestation key
// (256 bytes). It is signed twice: once with the RoT's firmware key and once
// with the RoT's device key, so that the CA can attest to both.
struct attestation_key_csr {
  struct keycert_header header;
  struct ec_p256_public_key public_key;
  struct ec_p256_signature firmware_signature;
  struct ec_p256_signature device_signature;
} __attribute__((packed));

// The attestation private key, encrypted with a key that never leaves the RoT
// (88 bytes). It is only meaningful to the RoT that produced it.
struct attestation_wrapped_key {
  uint8_t wrapper_version;
  uint8_t wrapper_purpose;
  uint8_t reserved_0[2];
  uint32_t data_size;
  uint8_t iv[ATTESTATION_KEY_WRAPPER_IV_SIZE];
  uint8_t hmac[ATTESTATION_KEY_WRAPPER_HMAC_SIZE];
  uint8_t encrypted_data[ATTESTATION_KEY_WRAPPER_DATA_SIZE];
} __attribute__((packed));

// Writes a certificate signing request in a human-readable form.
void htool_print_attestation_key_csr(FILE* out, int indent, const char* name,
                                     const struct attestation_key_csr* csr);

// Writes a wrapped attestation key in a human-readable form.
void htool_print_attestation_wrapped_key(
    FILE* out, int indent, const char* name,
    const struct attestation_wrapped_key* key);

// Generates a new attestation key and returns its signing request.
int htool_attestation_key_generate(const struct htool_invocation* inv);

// Installs an attestation key from a wrapped key and a signing request.
int htool_attestation_key_load_from_csr(const struct htool_invocation* inv);

// Removes the currently installed attestation key.
int htool_attestation_key_unload(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_ATTESTATION_KEY_H_
