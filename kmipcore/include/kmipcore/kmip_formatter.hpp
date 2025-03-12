#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace kmipcore {

  class Element;
  class RequestMessage;
  class ResponseMessage;

  /** @brief Formats an Element tree into a human-readable text dump. */
  [[nodiscard]] std::string format_element(const std::shared_ptr<Element> &element);
  /** @brief Formats a RequestMessage into a human-readable text dump. */
  [[nodiscard]] std::string format_request(const RequestMessage &request);
  /** @brief Formats a ResponseMessage into a human-readable text dump. */
  [[nodiscard]] std::string format_response(const ResponseMessage &response);
  /** @brief Parses and formats raw TTLV bytes into human-readable text. */
  [[nodiscard]] std::string format_ttlv(std::span<const uint8_t> ttlv);

}  // namespace kmipcore

