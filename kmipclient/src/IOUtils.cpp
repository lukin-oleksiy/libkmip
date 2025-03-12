/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; version 2 of
   the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "IOUtils.hpp"

#include "kmipclient/KmipIOException.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_formatter.hpp"
#include "kmipcore/kmip_logger.hpp"

#include <cstring>
#include <format>

namespace kmipclient {
#define KMIP_MSG_LENGTH_BYTES 8

  namespace {

    [[nodiscard]] int32_t read_int32_be(const uint8_t *bytes) {
      return (static_cast<int32_t>(bytes[0]) << 24) |
             (static_cast<int32_t>(bytes[1]) << 16) |
             (static_cast<int32_t>(bytes[2]) << 8) |
             static_cast<int32_t>(bytes[3]);
    }

  }  // namespace

  void IOUtils::log_debug(const char *event, std::span<const uint8_t> ttlv) const {
    try {
      if (!logger_ || !logger_->shouldLog(kmipcore::LogLevel::Debug)) {
        return;
      }

      logger_->log(kmipcore::LogRecord{
          .level = kmipcore::LogLevel::Debug,
          .component = "kmip.protocol",
          .event = event,
          .message = kmipcore::format_ttlv(ttlv)
      });
    } catch (...) {
      // Logging is strictly best-effort: protocol operations must not fail
      // because a custom logger threw.
    }
  }

  void IOUtils::send(const std::vector<uint8_t> &request_bytes) const {
    const int dlen = static_cast<int>(request_bytes.size());
    if (dlen <= 0) {
      throw KmipIOException(-1, "Can not send empty KMIP request.");
    }

    if (int sent = net_client.send(request_bytes.data(), dlen); sent < dlen) {
      throw KmipIOException(
          -1,
          std::format(
              "Can not send request. Bytes total: {}, bytes sent: {}",
              dlen,
              sent
          )
      );
    }
  }

  void IOUtils::read_exact(uint8_t *buf, int n) {
    int total_read = 0;
    while (total_read < n) {
      int received = net_client.recv(buf + total_read, n - total_read);
      if (received <= 0) {
        throw KmipIOException(
            -1,
            std::format(
                "Connection closed or error while reading. Expected {}, got {}",
                n,
                total_read
            )
        );
      }
      total_read += received;
    }
  }

  std::vector<uint8_t> IOUtils::receive_message(size_t max_message_size) {
    uint8_t msg_len_buf[KMIP_MSG_LENGTH_BYTES];

    read_exact(msg_len_buf, KMIP_MSG_LENGTH_BYTES);

    const int32_t length = read_int32_be(msg_len_buf + 4);
    if (length < 0 || static_cast<size_t>(length) > max_message_size) {
      throw KmipIOException(
          -1, std::format("Message too long. Length: {}", length)
      );
    }

    std::vector<uint8_t> response(
        KMIP_MSG_LENGTH_BYTES + static_cast<size_t>(length)
    );
    memcpy(response.data(), msg_len_buf, KMIP_MSG_LENGTH_BYTES);

    read_exact(response.data() + KMIP_MSG_LENGTH_BYTES, length);


    return response;
  }

  void IOUtils::do_exchange(
      const std::vector<uint8_t> &request_bytes,
      std::vector<uint8_t> &response_bytes,
      size_t max_message_size
  ) {
    try {
      log_debug("request", request_bytes);
      send(request_bytes);
      response_bytes = receive_message(max_message_size);
      log_debug("response", response_bytes);
    } catch (const KmipIOException &) {
      // Mark the underlying connection as dead so the pool (via
      // return_slot → is_connected() check) discards this slot
      // automatically — no need for the caller to call markUnhealthy().
      net_client.close();
      throw;
    }
  }

}  // namespace kmipclient
