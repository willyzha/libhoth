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

#include "transports/libhoth_fifo.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol/status.h"
#include "transports/libhoth_device.h"
#include "transports/libhoth_ec.h"

struct libhoth_fifo_device {
  int read_fd;
  int write_fd;
};

static libhoth_error libhoth_fifo_claim(struct libhoth_device* dev) {
  return HOTH_SUCCESS;
}

static libhoth_error libhoth_fifo_release(struct libhoth_device* dev) {
  return HOTH_SUCCESS;
}

static libhoth_error libhoth_fifo_reconnect(struct libhoth_device* dev) {
  return HOTH_SUCCESS;
}

static int read_exact_with_timeout(int fd, uint8_t* buf, size_t len,
                                   int timeout_ms) {
  size_t remaining = len;
  uint8_t* ptr = buf;

  while (remaining > 0) {
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret == 0) {
      return -ETIMEDOUT;
    }
    if (ret < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -errno;
    }
    if (!(pfd.revents & (POLLIN | POLLHUP))) {
      continue;
    }

    ssize_t n = read(fd, ptr, remaining);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -errno;
    }
    if (n == 0) {
      return -EPIPE;
    }
    ptr += n;
    remaining -= (size_t)n;
  }
  return 0;
}

libhoth_error libhoth_fifo_send_request(struct libhoth_device* dev,
                                       const void* request,
                                       size_t request_size) {
  if (!dev || !request || request_size == 0) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  struct libhoth_fifo_device* fifo_dev =
      (struct libhoth_fifo_device*)dev->user_ctx;
  if (!fifo_dev || fifo_dev->write_fd < 0) {
    return LIBHOTH_ERR_FAIL;
  }

  const uint8_t* ptr = (const uint8_t*)request;
  size_t remaining = request_size;
  while (remaining > 0) {
    ssize_t written = write(fifo_dev->write_fd, ptr, remaining);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return LIBHOTH_ERR_FAIL;
    }
    ptr += written;
    remaining -= (size_t)written;
  }
  return HOTH_SUCCESS;
}

libhoth_error libhoth_fifo_receive_response(struct libhoth_device* dev,
                                           void* response,
                                           size_t max_response_size,
                                           size_t* actual_size,
                                           int timeout_ms) {
  if (!dev || !response || max_response_size < sizeof(struct hoth_host_response)) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  struct libhoth_fifo_device* fifo_dev =
      (struct libhoth_fifo_device*)dev->user_ctx;
  if (!fifo_dev || fifo_dev->read_fd < 0) {
    return LIBHOTH_ERR_FAIL;
  }

  // Read response header
  int rc = read_exact_with_timeout(fifo_dev->read_fd, (uint8_t*)response,
                                   sizeof(struct hoth_host_response),
                                   timeout_ms);
  if (rc == -ETIMEDOUT) {
    return LIBHOTH_ERR_TIMEOUT;
  }
  if (rc != 0) {
    return LIBHOTH_ERR_FAIL;
  }

  struct hoth_host_response* resp_hdr = (struct hoth_host_response*)response;
  size_t total_size = sizeof(struct hoth_host_response) + resp_hdr->data_len;
  if (total_size > max_response_size) {
    return LIBHOTH_ERR_RESPONSE_BUFFER_OVERFLOW;
  }

  if (resp_hdr->data_len > 0) {
    rc = read_exact_with_timeout(
        fifo_dev->read_fd,
        (uint8_t*)response + sizeof(struct hoth_host_response),
        resp_hdr->data_len, timeout_ms);
    if (rc == -ETIMEDOUT) {
      return LIBHOTH_ERR_TIMEOUT;
    }
    if (rc != 0) {
      return LIBHOTH_ERR_FAIL;
    }
  }

  if (actual_size) {
    *actual_size = total_size;
  }
  return HOTH_SUCCESS;
}

libhoth_error libhoth_fifo_open(
    const struct libhoth_fifo_device_init_options* options,
    struct libhoth_device** out) {
  if (!options || !options->fifo_in || !options->fifo_out || !out) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }

  int read_fd = open(options->fifo_in, O_RDWR);
  if (read_fd < 0) {
    return LIBHOTH_ERR_FAIL;
  }

  int write_fd = open(options->fifo_out, O_RDWR);
  if (write_fd < 0) {
    close(read_fd);
    return LIBHOTH_ERR_FAIL;
  }

  struct libhoth_device* dev = calloc(1, sizeof(struct libhoth_device));
  if (!dev) {
    close(read_fd);
    close(write_fd);
    return LIBHOTH_ERR_MALLOC_FAILED;
  }

  struct libhoth_fifo_device* fifo_dev =
      calloc(1, sizeof(struct libhoth_fifo_device));
  if (!fifo_dev) {
    free(dev);
    close(read_fd);
    close(write_fd);
    return LIBHOTH_ERR_MALLOC_FAILED;
  }

  fifo_dev->read_fd = read_fd;
  fifo_dev->write_fd = write_fd;

  dev->send = libhoth_fifo_send_request;
  dev->receive = libhoth_fifo_receive_response;
  dev->close = libhoth_fifo_close;
  dev->claim = libhoth_fifo_claim;
  dev->release = libhoth_fifo_release;
  dev->reconnect = libhoth_fifo_reconnect;
  dev->user_ctx = fifo_dev;

  *out = dev;
  return HOTH_SUCCESS;
}

libhoth_error libhoth_fifo_close(struct libhoth_device* dev) {
  if (!dev) {
    return LIBHOTH_ERR_INVALID_PARAMETER;
  }
  struct libhoth_fifo_device* fifo_dev =
      (struct libhoth_fifo_device*)dev->user_ctx;
  if (fifo_dev) {
    if (fifo_dev->read_fd >= 0) {
      close(fifo_dev->read_fd);
    }
    if (fifo_dev->write_fd >= 0) {
      close(fifo_dev->write_fd);
    }
    free(fifo_dev);
    dev->user_ctx = NULL;
  }
  free(dev);
  return HOTH_SUCCESS;
}
