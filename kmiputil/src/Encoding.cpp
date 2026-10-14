/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "Encoding.hpp"

#include "kmipcore/kmip_errors.hpp"

#include <array>

namespace kmiputil::encoding {

  namespace {

    constexpr std::string_view kHexDigits = "0123456789abcdef";
    constexpr std::string_view kBase64Alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    unsigned char hex_value(const char c) {
      if (c >= '0' && c <= '9') {
        return static_cast<unsigned char>(c - '0');
      }
      if (c >= 'A' && c <= 'F') {
        return static_cast<unsigned char>(c - 'A' + 10);
      }
      if (c >= 'a' && c <= 'f') {
        return static_cast<unsigned char>(c - 'a' + 10);
      }
      throw kmipcore::KmipException{"Invalid hex character."};
    }

    // Line breaks and spaces are allowed anywhere in Base64 input, e.g.
    // between the lines of a PEM body.
    bool is_base64_whitespace(const unsigned char c) {
      return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

  }  // namespace

  kmipcore::secure_bytes from_hex(std::string_view hex) {
    if (hex.empty() || hex.size() % 2 != 0) {
      throw kmipcore::KmipException{"Invalid hex string length."};
    }
    kmipcore::secure_bytes bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
      bytes.push_back(
          static_cast<unsigned char>(
              hex_value(hex[i]) * 16 + hex_value(hex[i + 1])
          )
      );
    }
    return bytes;
  }

  kmipcore::secure_string to_hex(std::span<const unsigned char> bytes) {
    kmipcore::secure_string out;
    out.reserve(bytes.size() * 2);
    for (const unsigned char b : bytes) {
      out.push_back(kHexDigits[b >> 4]);
      out.push_back(kHexDigits[b & 0x0F]);
    }
    return out;
  }

  kmipcore::secure_bytes from_base64(std::string_view base64) {
    static const std::array<int, 256> lookup = []() {
      std::array<int, 256> l{};
      l.fill(-1);
      for (size_t i = 0; i < kBase64Alphabet.size(); ++i) {
        l[static_cast<unsigned char>(kBase64Alphabet[i])] = static_cast<int>(i);
      }
      return l;
    }();

    kmipcore::secure_bytes out;
    out.reserve((base64.size() / 4) * 3);

    int val = 0, val_b = -8;
    size_t symbols = 0;  // alphabet and padding characters, not whitespace
    size_t padding = 0;
    for (const unsigned char c : base64) {
      if (is_base64_whitespace(c)) {
        continue;
      }
      ++symbols;
      if (c == '=') {
        ++padding;
        continue;
      }
      if (lookup[c] == -1) {
        throw kmipcore::KmipException{"Invalid Base64 character."};
      }
      if (padding > 0) {
        throw kmipcore::KmipException{"Invalid Base64: data after padding."};
      }
      val = (val << 6) + lookup[c];
      val_b += 6;
      if (val_b >= 0) {
        out.push_back(static_cast<unsigned char>((val >> val_b) & 0xFF));
        val_b -= 8;
      }
    }
    if (symbols % 4 != 0 || padding > 2) {
      throw kmipcore::KmipException{"Invalid Base64 length or padding."};
    }
    // The bits of the last character that no output byte used must be zero,
    // or e.g. "Zh==" and "Zg==" would both decode to "f" (RFC 4648 §3.5).
    const int unused_bits = val_b + 8;
    if (unused_bits > 0 && (val & ((1 << unused_bits) - 1)) != 0) {
      throw kmipcore::KmipException{"Non-canonical Base64 padding bits."};
    }
    return out;
  }

  kmipcore::secure_string to_base64(std::span<const unsigned char> bytes) {
    kmipcore::secure_string out;
    out.reserve(((bytes.size() + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= bytes.size(); i += 3) {
      const unsigned int n =
          (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out.push_back(kBase64Alphabet[(n >> 18) & 0x3F]);
      out.push_back(kBase64Alphabet[(n >> 12) & 0x3F]);
      out.push_back(kBase64Alphabet[(n >> 6) & 0x3F]);
      out.push_back(kBase64Alphabet[n & 0x3F]);
    }
    const size_t rest = bytes.size() - i;
    if (rest > 0) {
      unsigned int n = bytes[i] << 16;
      if (rest == 2) {
        n |= bytes[i + 1] << 8;
      }
      out.push_back(kBase64Alphabet[(n >> 18) & 0x3F]);
      out.push_back(kBase64Alphabet[(n >> 12) & 0x3F]);
      out.push_back(rest == 2 ? kBase64Alphabet[(n >> 6) & 0x3F] : '=');
      out.push_back('=');
    }
    return out;
  }

}  // namespace kmiputil::encoding
