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

#include "htool_dice_certs.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void htool_print_hex_string(FILE* out, const uint8_t* data, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    fprintf(out, "%02x", data[i]);
  }
}

void htool_print_hex_field(FILE* out, int indent, const char* name,
                           const uint8_t* data, size_t size) {
  fprintf(out, "%*s%s: ", indent, "", name);
  htool_print_hex_string(out, data, size);
  fprintf(out, "\n");
}

void htool_print_ec_p256_public_key(FILE* out, int indent, const char* name,
                                    const struct ec_p256_public_key* key) {
  fprintf(out, "%*s%s:\n", indent, "", name);
  htool_print_hex_field(out, indent + 2, "q_a_x", key->q_a_x,
                        sizeof(key->q_a_x));
  htool_print_hex_field(out, indent + 2, "q_a_y", key->q_a_y,
                        sizeof(key->q_a_y));
}

void htool_print_ec_p256_signature(FILE* out, int indent, const char* name,
                                   const struct ec_p256_signature* signature) {
  fprintf(out, "%*s%s:\n", indent, "", name);
  htool_print_hex_field(out, indent + 2, "r", signature->r,
                        sizeof(signature->r));
  htool_print_hex_field(out, indent + 2, "s", signature->s,
                        sizeof(signature->s));
}

void htool_print_keycert_header(FILE* out, int indent, const char* name,
                                const struct keycert_header* header) {
  const int body = indent + 2;
  fprintf(out, "%*s%s:\n", indent, "", name);
  fprintf(out, "%*ssignature_version: %" PRIu32 "\n", body, "",
          header->signature_version);
  fprintf(out, "%*ssignature_purpose: %" PRIu32 "\n", body, "",
          header->signature_purpose);
  fprintf(out, "%*sextension_header_type: %u\n", body, "",
          header->extension_header_type);
  fprintf(out, "%*skey_type: %u\n", body, "", header->key_type);
  fprintf(out, "%*skey_op: %u\n", body, "", header->key_op);
  fprintf(out, "%*skey_alg: %u\n", body, "", header->key_alg);
  htool_print_hex_field(out, body, "key_info", header->key_info,
                        sizeof(header->key_info));
  htool_print_hex_field(out, body, "cert_validity", header->cert_validity,
                        sizeof(header->cert_validity));
  fprintf(out, "%*shw_id: 0x%016" PRIx64 "\n", body, "", header->hw_id);
  fprintf(out, "%*shw_cat: %u\n", body, "", header->hw_cat);
  fprintf(out, "%*sbootloader_tag: 0x%08" PRIx32 "\n", body, "",
          header->bootloader_tag);
  fprintf(out, "%*sfw_epoch: %" PRIu32 "\n", body, "", header->fw_epoch);
  fprintf(out, "%*sfw_major_version: %u\n", body, "", header->fw_major_version);
  fprintf(out, "%*spub_key_size: %u\n", body, "", header->pub_key_size);
}

static void print_device_id_keycert_header(
    FILE* out, int indent, const char* name,
    const struct device_id_keycert_header* header) {
  const int body = indent + 2;
  fprintf(out, "%*s%s:\n", indent, "", name);
  fprintf(out, "%*ssignature_version: %" PRIu32 "\n", body, "",
          header->signature_version);
  fprintf(out, "%*ssignature_purpose: %" PRIu32 "\n", body, "",
          header->signature_purpose);
  fprintf(out, "%*sextension_header_type: %u\n", body, "",
          header->extension_header_type);
  fprintf(out, "%*skey_type: %u\n", body, "", header->key_type);
  fprintf(out, "%*skey_op: %u\n", body, "", header->key_op);
  fprintf(out, "%*skey_alg: %u\n", body, "", header->key_alg);
  htool_print_hex_field(out, body, "key_info", header->key_info,
                        sizeof(header->key_info));
  htool_print_hex_field(out, body, "cert_validity", header->cert_validity,
                        sizeof(header->cert_validity));
  htool_print_hex_field(out, body, "endorsement_key_id",
                        header->endorsement_key_id,
                        sizeof(header->endorsement_key_id));
  fprintf(out, "%*shw_id: 0x%016" PRIx64 "\n", body, "", header->hw_id);
  fprintf(out, "%*shw_cat: %u\n", body, "", header->hw_cat);
  fprintf(out, "%*ssigned_data_size: %u\n", body, "", header->signed_data_size);
  fprintf(out, "%*sbootloader_tag: 0x%08" PRIx32 "\n", body, "",
          header->bootloader_tag);
}

void htool_print_alias_key_certificate(FILE* out, int indent, const char* name,
                                       const struct alias_key_certificate* cert,
                                       const uint8_t* fw_hash) {
  const int body = indent + 2;
  fprintf(out, "%*s%s:\n", indent, "", name);
  htool_print_keycert_header(out, body, "header", &cert->header);
  htool_print_ec_p256_public_key(out, body, "public_key", &cert->public_key);
  htool_print_ec_p256_signature(out, body, "signature", &cert->signature);
  if (fw_hash != NULL) {
    htool_print_hex_field(out, body, "fw_hash", fw_hash, KEYCERT_FW_HASH_SIZE);
  }
}

void htool_print_device_id_certificate(
    FILE* out, int indent, const char* name,
    const struct device_id_certificate* cert) {
  const int body = indent + 2;
  fprintf(out, "%*s%s:\n", indent, "", name);
  print_device_id_keycert_header(out, body, "header", &cert->header);
  htool_print_ec_p256_public_key(out, body, "key", &cert->key);
  htool_print_ec_p256_signature(out, body, "signature", &cert->signature);
}

void htool_print_device_id_endorsement_certificate(
    FILE* out, int indent, const char* name,
    const struct device_id_endorsement_certificate* cert) {
  const int body = indent + 2;
  fprintf(out, "%*s%s:\n", indent, "", name);
  htool_print_hex_field(out, body, "device_id_cert_hash",
                        cert->device_id_cert_hash,
                        sizeof(cert->device_id_cert_hash));
  htool_print_ec_p256_public_key(out, body, "endorsement_rw_key",
                                 &cert->endorsement_rw_key);
  htool_print_ec_p256_signature(out, body, "signature", &cert->signature);
}

void htool_print_dice_certificate_chain(
    FILE* out, int indent, const char* name,
    const struct dice_certificate_chain* chain) {
  const int body = indent + 2;
  fprintf(out, "%*s%s:\n", indent, "", name);
  htool_print_alias_key_certificate(out, body, "alias_key_certificate",
                                    &chain->alias_key_certificate.cert,
                                    chain->alias_key_certificate.fw_hash);
  htool_print_device_id_certificate(out, body, "device_id_certificate",
                                    &chain->device_id_certificate);
  htool_print_device_id_endorsement_certificate(
      out, body, "device_id_endorsement_certificate",
      &chain->device_id_endorsement_certificate);
}
