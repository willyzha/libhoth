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

#include "htool_attestation_key.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"
#include "htool_dice_certs.h"
#include "htool_macros.h"
#include "htool_security_v2.h"
#include "protocol/host_cmd.h"
#include "protocol/util.h"
#include "transports/libhoth_device.h"

void htool_print_attestation_key_csr(FILE* out, int indent, const char* name,
                                     const struct attestation_key_csr* csr) {
  fprintf(out, "%*s%s:\n", indent, "", name);
  htool_print_keycert_header(out, indent + 2, "header", &csr->header);
  htool_print_ec_p256_public_key(out, indent + 2, "public_key",
                                 &csr->public_key);
  htool_print_ec_p256_signature(out, indent + 2, "firmware_signature",
                                &csr->firmware_signature);
  htool_print_ec_p256_signature(out, indent + 2, "device_signature",
                                &csr->device_signature);
}

void htool_print_attestation_wrapped_key(
    FILE* out, int indent, const char* name,
    const struct attestation_wrapped_key* key) {
  fprintf(out, "%*s%s:\n", indent, "", name);
  fprintf(out, "%*swrapper_version: %" PRIu8 "\n", indent + 2, "",
          key->wrapper_version);
  fprintf(out, "%*swrapper_purpose: %" PRIu8 "\n", indent + 2, "",
          key->wrapper_purpose);
  fprintf(out, "%*sdata_size: %" PRIu32 "\n", indent + 2, "", key->data_size);
  htool_print_hex_field(out, indent + 2, "iv", key->iv, sizeof(key->iv));
  htool_print_hex_field(out, indent + 2, "hmac", key->hmac, sizeof(key->hmac));
  htool_print_hex_field(out, indent + 2, "encrypted_data", key->encrypted_data,
                        sizeof(key->encrypted_data));
}

// Writes `data` to the file named by the `name` parameter, if that parameter
// was given a non-empty value.
//
// The bytes are written verbatim: the CA tooling that consumes a signing
// request, and the RoT that later consumes a wrapped key, both expect the
// exact bytes the RoT produced rather than the rendering printed to stdout.
static int write_optional_output(const struct htool_invocation* inv,
                                 const char* name, const void* data,
                                 size_t size) {
  const char* path;
  if (htool_get_param_string(inv, name, &path) != 0) {
    return -1;
  }
  if (strlen(path) == 0) {
    return 0;
  }

  FILE* file = fopen(path, "wb");
  if (file == NULL) {
    fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
            strerror(errno), path);
    return -1;
  }
  const size_t written = fwrite(data, 1, size, file);
  const bool failed = (written != size) || (fclose(file) != 0);
  if (failed) {
    fprintf(stderr, "Error: %s, when writing file: %s\n", strerror(errno),
            path);
    return -1;
  }
  return 0;
}

// Reads exactly `size` bytes into `out` from either the file named by the
// `file_param` parameter or the hex string given in the `hex_param` parameter.
// Exactly one of the two must be provided.
static int read_fixed_blob(const struct htool_invocation* inv,
                           const char* file_param, const char* hex_param,
                           uint8_t* out, size_t size) {
  const char* path;
  const char* hex;
  if (htool_get_param_string(inv, file_param, &path) != 0 ||
      htool_get_param_string(inv, hex_param, &hex) != 0) {
    return -1;
  }

  const bool has_file = strlen(path) > 0;
  const bool has_hex = strlen(hex) > 0;
  if (has_file == has_hex) {
    fprintf(stderr, "Exactly one of --%s or --%s must be specified.\n",
            file_param, hex_param);
    return -1;
  }

  if (has_hex) {
    size_t parsed = 0;
    if (libhoth_parse_hex_string(hex, out, size, &parsed) != 0 ||
        parsed != size) {
      fprintf(stderr, "--%s must be a hex string of exactly %zu bytes.\n",
              hex_param, size);
      return -1;
    }
    return 0;
  }

  FILE* file = fopen(path, "rb");
  if (file == NULL) {
    fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
            strerror(errno), path);
    return -1;
  }
  const size_t read = fread(out, 1, size, file);
  const bool has_trailing_bytes = fgetc(file) != EOF;
  const bool read_error = ferror(file) != 0;
  fclose(file);

  if (read_error) {
    fprintf(stderr, "Error reading %s\n", path);
    return -1;
  }
  if (read != size || has_trailing_bytes) {
    fprintf(stderr, "%s must contain exactly %zu bytes.\n", path, size);
    return -1;
  }
  return 0;
}

int htool_attestation_key_generate(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct attestation_key_csr csr = {0};
  struct attestation_wrapped_key wrapped_key = {0};

  uint8_t request_storage[HOTH_SECURITY_V2_REQUEST_SIZE(0)] = {};
  uint8_t response_storage[HOTH_SECURITY_V2_RESPONSE_SIZE(2) + sizeof(csr) +
                           sizeof(wrapped_key)] = {};
  struct security_v2_param response_params[] = {
      {.data = &csr, .size = sizeof(csr)},
      {.data = &wrapped_key, .size = sizeof(wrapped_key)},
  };

  int status = htool_exec_security_v2_cmd(
      dev,
      /*major=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      /*minor=*/
      HOTH_PRV_CMD_HOTH_SECURITY_V2_GENERATE_ATTESTATION_KEY_MINOR_COMMAND,
      /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
      SECURITY_V2_BUFFER_PARAM(request_storage), NULL, 0,
      SECURITY_V2_BUFFER_PARAM(response_storage), response_params,
      ARRAY_SIZE(response_params));
  if (status != 0) {
    fprintf(stderr,
            "Unexpected Error: Returned status %d, while trying to generate "
            "the attestation key\n",
            status);
    return status;
  }

  htool_print_attestation_key_csr(stdout, 0, "Certificate Signing Request",
                                  &csr);
  htool_print_attestation_wrapped_key(stdout, 0, "Wrapped Key", &wrapped_key);

  // The wrapped key is the only copy of the private key, and the signing
  // request is needed to get a certificate for it, so print both as hex too.
  // Operators routinely have to carry these to another machine, and a hex
  // string survives a copy/paste where a binary file does not.
  printf("\nCertificate Signing Request (hex):\n");
  htool_print_hex_string(stdout, (const uint8_t*)&csr, sizeof(csr));
  printf("\n\nWrapped Key (hex):\n");
  htool_print_hex_string(stdout, (const uint8_t*)&wrapped_key,
                         sizeof(wrapped_key));
  printf("\n");

  if (write_optional_output(inv, "csr_output", &csr, sizeof(csr)) != 0 ||
      write_optional_output(inv, "wrapped_key_output", &wrapped_key,
                            sizeof(wrapped_key)) != 0) {
    return -1;
  }
  return 0;
}

int htool_attestation_key_load_from_csr(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct attestation_wrapped_key wrapped_key = {0};
  struct attestation_key_csr csr = {0};
  if (read_fixed_blob(inv, "wrapped_key", "wrapped_key_hex",
                      (uint8_t*)&wrapped_key, sizeof(wrapped_key)) != 0 ||
      read_fixed_blob(inv, "csr", "csr_hex", (uint8_t*)&csr, sizeof(csr)) !=
          0) {
    return -1;
  }

  uint8_t request_storage[HOTH_SECURITY_V2_REQUEST_SIZE(2) +
                          sizeof(wrapped_key) + sizeof(csr)] = {};
  uint8_t response_storage[HOTH_SECURITY_V2_RESPONSE_SIZE(0)] = {};
  const struct security_v2_param request_params[] = {
      {.data = &wrapped_key, .size = sizeof(wrapped_key)},
      {.data = &csr, .size = sizeof(csr)},
  };

  int status = htool_exec_security_v2_cmd(
      dev,
      /*major=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      /*minor=*/
      HOTH_PRV_CMD_HOTH_SECURITY_V2_LOAD_ATTESTATION_KEY_FROM_CSR_MINOR_COMMAND,
      /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
      SECURITY_V2_BUFFER_PARAM(request_storage), request_params,
      ARRAY_SIZE(request_params), SECURITY_V2_BUFFER_PARAM(response_storage),
      NULL, 0);
  if (status != 0) {
    fprintf(stderr,
            "Unexpected Error: Returned status %d, while trying to load the "
            "attestation key\n",
            status);
    return status;
  }

  printf("Attestation key loaded\n");
  return 0;
}

int htool_attestation_key_unload(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  uint8_t request_storage[HOTH_SECURITY_V2_REQUEST_SIZE(0)] = {};
  uint8_t response_storage[HOTH_SECURITY_V2_RESPONSE_SIZE(0)] = {};

  int status = htool_exec_security_v2_cmd(
      dev,
      /*major=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      /*minor=*/
      HOTH_PRV_CMD_HOTH_SECURITY_V2_UNLOAD_ATTESTATION_KEY_MINOR_COMMAND,
      /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
      SECURITY_V2_BUFFER_PARAM(request_storage), NULL, 0,
      SECURITY_V2_BUFFER_PARAM(response_storage), NULL, 0);
  if (status != 0) {
    fprintf(stderr,
            "Unexpected Error: Returned status %d, while trying to unload the "
            "attestation key\n",
            status);
    return status;
  }

  printf("Attestation key unloaded\n");
  return 0;
}
