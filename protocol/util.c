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

#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

uint64_t libhoth_get_monotonic_ms() {
  struct timespec ts;
  int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (ret != 0) {
    perror("clock_gettime failed");
    // Very unlikely to happen and probably not
    // possible to recover from this.
    exit(ret);
  }
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

uint32_t libhoth_prng_seed() {
  // TODO: Can we just use rand() here?
  struct timespec ts;
  int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (ret != 0) {
    perror("clock_gettime failed");
    // Very unlikely to happen and probably not
    // possible to recover from this.
    exit(ret);
  }
  return ts.tv_sec ^ ts.tv_nsec ^ getpid();
}

int libhoth_force_write(int fd, const void* buf, size_t count) {
  const char* cbuf = buf;
  while (count > 0) {
    ssize_t bytes_written = write(fd, cbuf, count);
    if (bytes_written < 0) {
      return errno;
    }
    cbuf += bytes_written;
    count -= bytes_written;
  }
  return 0;
}

static int hex_digit_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

int libhoth_parse_hex_string(const char* hex, uint8_t* out, size_t out_size,
                             size_t* out_len) {
  if (hex == NULL || out == NULL || out_len == NULL) {
    return -1;
  }

  size_t hex_len = strlen(hex);
  if (hex_len == 0 || hex_len % 2 != 0 || hex_len / 2 > out_size) {
    return -1;
  }

  for (size_t i = 0; i < hex_len; i += 2) {
    int hi = hex_digit_value(hex[i]);
    int lo = hex_digit_value(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    out[i / 2] = (uint8_t)((hi << 4) | lo);
  }
  *out_len = hex_len / 2;
  return 0;
}
