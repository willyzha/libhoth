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

#include "htool_secret_provisioning.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "htool.h"
#include "htool_cmd.h"
#include "htool_dice_certs.h"
#include "protocol/secret_provisioning.h"
#include "protocol/util.h"
#include "transports/libhoth_device.h"

static void print_encryption_key_certificate(
    FILE* out, const struct provisioning_encryption_key_certificate* cert) {
  fprintf(out, "Encryption Key Certificate:\n");
  fprintf(out, "  header:\n");
  fprintf(out, "    signature_version: %" PRIu32 "\n",
          cert->header.signature_version);
  htool_print_hex_field(out, 4, "key_identifier", cert->header.key_identifier,
                        sizeof(cert->header.key_identifier));
  fprintf(out, "    key_size: %" PRIu32 "\n", cert->header.key_size);
  fprintf(out, "    key_type: %" PRIu32 "\n", cert->header.key_type);
  fprintf(out, "    key_op: %" PRIu32 "\n", cert->header.key_op);
  htool_print_ec_p256_public_key(out, 2, "public_key", &cert->public_key);
  htool_print_ec_p256_signature(out, 2, "signature", &cert->signature);
}

void htool_print_provisioning_encryption_key_certificate_chain(
    FILE* out,
    const struct provisioning_encryption_key_certificate_chain* chain) {
  print_encryption_key_certificate(out, &chain->encryption_key_cert);
  htool_print_dice_certificate_chain(out, 0, "DICE Certificate Chain",
                                     &chain->dice_certificate_chain);
}

int htool_provisioning_get_encryption_key(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* output_file;
  if (htool_get_param_string(inv, "output", &output_file) != 0) {
    return -1;
  }

  struct provisioning_encryption_key_certificate_chain chain;
  size_t response_size = 0;
  libhoth_error err = libhoth_secret_provisioning_get_encryption_key(
      dev, &chain, sizeof(chain), &response_size);
  if (err != HOTH_SUCCESS) {
    htool_report_error("secret_provisioning_get_encryption_key", err);
    return -1;
  }
  if (response_size != sizeof(chain)) {
    fprintf(stderr,
            "Unexpected encryption key response size. Expecting %zu; Got %zu\n",
            sizeof(chain), response_size);
    return -1;
  }

  htool_print_provisioning_encryption_key_certificate_chain(stdout, &chain);

  // Verification and signing tools consume the certificate chain as-is, so
  // write out the unmodified response rather than the rendering above.
  if (strlen(output_file) > 0) {
    FILE* output = fopen(output_file, "wb");
    if (output == NULL) {
      fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
              strerror(errno), output_file);
      return -1;
    }
    const size_t written = fwrite(&chain, 1, sizeof(chain), output);
    const bool write_failed =
        (written != sizeof(chain)) || (fclose(output) != 0);
    if (write_failed) {
      fprintf(stderr, "Error: %s, when writing file: %s\n", strerror(errno),
              output_file);
      return -1;
    }
  }
  return 0;
}

// Reads the encrypted secrets from either `--secrets` (a binary file, as
// produced by the offline encryption tools) or `--hex` (the same bytes as a
// hex string, which is easier to paste into a remote shell).
static int get_secrets(const struct htool_invocation* inv, uint8_t* secrets,
                       size_t secrets_capacity, size_t* secrets_size) {
  const char* secrets_file;
  const char* secrets_hex;
  if (htool_get_param_string(inv, "secrets", &secrets_file) != 0 ||
      htool_get_param_string(inv, "hex", &secrets_hex) != 0) {
    return -1;
  }

  const bool has_file = strlen(secrets_file) > 0;
  const bool has_hex = strlen(secrets_hex) > 0;
  if (has_file == has_hex) {
    fprintf(stderr, "Exactly one of --secrets or --hex must be specified.\n");
    return -1;
  }

  if (has_hex) {
    if (libhoth_parse_hex_string(secrets_hex, secrets, secrets_capacity,
                                 secrets_size) != 0) {
      fprintf(stderr,
              "Unable to parse --hex as a hex string of at most %zu bytes.\n",
              secrets_capacity);
      return -1;
    }
    return 0;
  }

  FILE* file = fopen(secrets_file, "rb");
  if (file == NULL) {
    fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
            strerror(errno), secrets_file);
    return -1;
  }

  *secrets_size = fread(secrets, 1, secrets_capacity, file);
  // A full buffer may mean the file was truncated; check for trailing bytes.
  const bool too_large =
      (*secrets_size == secrets_capacity) && (fgetc(file) != EOF);
  const bool read_error = ferror(file) != 0;
  fclose(file);

  if (read_error) {
    fprintf(stderr, "Error reading %s\n", secrets_file);
    return -1;
  }
  if (too_large) {
    fprintf(stderr, "%s is larger than the maximum of %zu bytes\n",
            secrets_file, secrets_capacity);
    return -1;
  }
  if (*secrets_size == 0) {
    fprintf(stderr, "%s is empty\n", secrets_file);
    return -1;
  }
  return 0;
}

int htool_provisioning_store_secrets(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  uint8_t secrets[HOTH_SECRET_PROVISIONING_MAX_SECRETS_SIZE];
  size_t secrets_size = 0;
  if (get_secrets(inv, secrets, sizeof(secrets), &secrets_size) != 0) {
    return -1;
  }

  libhoth_error err =
      libhoth_secret_provisioning_store_secrets(dev, secrets, secrets_size);
  if (err != HOTH_SUCCESS) {
    htool_report_error("secret_provisioning_store_secrets", err);
    return -1;
  }
  printf("Stored %zu bytes of encrypted secrets\n", secrets_size);
  return 0;
}
