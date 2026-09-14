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

#ifndef _LIBHOTH_TRANSPORTS_LIBHOTH_FIFO_H_
#define _LIBHOTH_TRANSPORTS_LIBHOTH_FIFO_H_

#include <stddef.h>
#include <stdint.h>

#include "protocol/status.h"
#include "transports/libhoth_device.h"

#ifdef __cplusplus
extern "C" {
#endif

struct libhoth_fifo_device_init_options {
  // Path to the FIFO for reading responses.
  const char* fifo_in;
  // Path to the FIFO for writing requests.
  const char* fifo_out;
};

libhoth_error libhoth_fifo_open(
    const struct libhoth_fifo_device_init_options* options,
    struct libhoth_device** out);

libhoth_error libhoth_fifo_close(struct libhoth_device* dev);

libhoth_error libhoth_fifo_send_request(struct libhoth_device* dev,
                                       const void* request,
                                       size_t request_size);

libhoth_error libhoth_fifo_receive_response(struct libhoth_device* dev,
                                           void* response,
                                           size_t max_response_size,
                                           size_t* actual_size,
                                           int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif  // _LIBHOTH_TRANSPORTS_LIBHOTH_FIFO_H_
