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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "protocol/status.h"
#include "transports/libhoth_device.h"
#include "transports/libhoth_ec.h"

namespace {

class LibhothFifoTest : public ::testing::Test {
 protected:
  void SetUp() override {
    char templ[] = "/tmp/libhoth_fifo_test_XXXXXX";
    char* dir = mkdtemp(templ);
    ASSERT_NE(dir, nullptr);
    temp_dir_ = dir;
    fifo_in_path_ = temp_dir_ + "/fifo_in";
    fifo_out_path_ = temp_dir_ + "/fifo_out";

    ASSERT_EQ(mkfifo(fifo_in_path_.c_str(), 0600), 0);
    ASSERT_EQ(mkfifo(fifo_out_path_.c_str(), 0600), 0);
  }

  void TearDown() override {
    unlink(fifo_in_path_.c_str());
    unlink(fifo_out_path_.c_str());
    rmdir(temp_dir_.c_str());
  }

  std::string temp_dir_;
  std::string fifo_in_path_;
  std::string fifo_out_path_;
};

TEST_F(LibhothFifoTest, InvalidParams) {
  struct libhoth_device* dev = nullptr;
  EXPECT_EQ(libhoth_fifo_open(nullptr, &dev), LIBHOTH_ERR_INVALID_PARAMETER);

  struct libhoth_fifo_device_init_options options = {
      .fifo_in = nullptr,
      .fifo_out = fifo_out_path_.c_str(),
  };
  EXPECT_EQ(libhoth_fifo_open(&options, &dev), LIBHOTH_ERR_INVALID_PARAMETER);

  options.fifo_in = fifo_in_path_.c_str();
  options.fifo_out = nullptr;
  EXPECT_EQ(libhoth_fifo_open(&options, &dev), LIBHOTH_ERR_INVALID_PARAMETER);

  options.fifo_out = fifo_out_path_.c_str();
  EXPECT_EQ(libhoth_fifo_open(&options, nullptr), LIBHOTH_ERR_INVALID_PARAMETER);
}

TEST_F(LibhothFifoTest, SendAndReceive) {
  struct libhoth_fifo_device_init_options options = {
      .fifo_in = fifo_in_path_.c_str(),
      .fifo_out = fifo_out_path_.c_str(),
  };
  struct libhoth_device* dev = nullptr;
  ASSERT_EQ(libhoth_fifo_open(&options, &dev), HOTH_SUCCESS);
  ASSERT_NE(dev, nullptr);

  // Send a request
  const uint8_t req_data[] = {0x01, 0x02, 0x03, 0x04};
  EXPECT_EQ(dev->send(dev, req_data, sizeof(req_data)), HOTH_SUCCESS);

  // Read the request from the other end of fifo_out
  int out_fd = open(fifo_out_path_.c_str(), O_RDONLY | O_NONBLOCK);
  ASSERT_GE(out_fd, 0);
  uint8_t read_buf[sizeof(req_data)] = {0};
  ssize_t n = read(out_fd, read_buf, sizeof(read_buf));
  EXPECT_EQ(n, sizeof(req_data));
  EXPECT_THAT(std::vector<uint8_t>(read_buf, read_buf + n),
              ::testing::ElementsAre(0x01, 0x02, 0x03, 0x04));
  close(out_fd);

  // Write a mock response to fifo_in
  int in_fd = open(fifo_in_path_.c_str(), O_WRONLY | O_NONBLOCK);
  ASSERT_GE(in_fd, 0);
  struct hoth_host_response resp_hdr = {
      .struct_version = 3,
      .checksum = 0,
      .result = 0,
      .data_len = 2,
      .reserved = 0,
  };
  uint8_t resp_payload[] = {0xAA, 0xBB};
  ASSERT_EQ(write(in_fd, &resp_hdr, sizeof(resp_hdr)), sizeof(resp_hdr));
  ASSERT_EQ(write(in_fd, resp_payload, sizeof(resp_payload)), sizeof(resp_payload));
  close(in_fd);

  // Receive response
  uint8_t resp_buf[64] = {0};
  size_t actual_size = 0;
  EXPECT_EQ(dev->receive(dev, resp_buf, sizeof(resp_buf), &actual_size, 1000),
            HOTH_SUCCESS);
  EXPECT_EQ(actual_size, sizeof(resp_hdr) + sizeof(resp_payload));
  EXPECT_EQ(resp_buf[sizeof(resp_hdr)], 0xAA);
  EXPECT_EQ(resp_buf[sizeof(resp_hdr) + 1], 0xBB);

  EXPECT_EQ(dev->close(dev), HOTH_SUCCESS);
}

TEST_F(LibhothFifoTest, ReceiveTimeout) {
  struct libhoth_fifo_device_init_options options = {
      .fifo_in = fifo_in_path_.c_str(),
      .fifo_out = fifo_out_path_.c_str(),
  };
  struct libhoth_device* dev = nullptr;
  ASSERT_EQ(libhoth_fifo_open(&options, &dev), HOTH_SUCCESS);
  ASSERT_NE(dev, nullptr);

  uint8_t resp_buf[64] = {0};
  size_t actual_size = 0;
  // Should timeout quickly (50ms)
  EXPECT_EQ(dev->receive(dev, resp_buf, sizeof(resp_buf), &actual_size, 50),
            LIBHOTH_ERR_TIMEOUT);

  EXPECT_EQ(dev->close(dev), HOTH_SUCCESS);
}

}  // namespace
