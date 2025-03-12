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

#ifndef KMIPCLIENT_KEY_HPP
#define KMIPCLIENT_KEY_HPP

#include "kmipclient/types.hpp"
#include "kmipcore/key.hpp"

#include <utility>

namespace kmipclient {

  /**
   * Client-level crypto key extending the core Key with convenience
   * factory methods for creating keys from hex, base64, PEM, etc.
   */
  class Key : public kmipcore::Key {
  public:
    // Inherit all base-class constructors
    using kmipcore::Key::Key;

    /**
     * @brief Implicitly wraps an existing core key object.
     * @param base Source key instance.
     */
    Key(kmipcore::Key base)
      : kmipcore::Key(std::move(base)) {
    }  // NOLINT(google-explicit-constructor)

    /** @brief Constructs an empty key instance. */
    Key() = default;

    /**
     * @brief Creates an AES symmetric key from a hexadecimal string.
     * @param hex Hex-encoded key bytes.
     * @return Initialized AES key.
     * @throws kmipcore::KmipException when decoding fails.
     */
    static Key aes_from_hex(const std::string &hex);
    /**
     * @brief Creates an AES symmetric key from a Base64 string.
     * @param base64 Base64-encoded key bytes.
     * @return Initialized AES key.
     * @throws kmipcore::KmipException when decoding fails.
     */
    static Key aes_from_base64(const std::string &base64);

    /**
     * @brief Creates an AES symmetric key from raw bytes.
     * @param val Binary key value.
     * @return Initialized AES key.
     */
    static Key aes_from_value(const std::vector<unsigned char> &val);
    /**
     * @brief Generates a random AES key of the requested size.
     * @param size_bits Key size in bits. Supported values: 128, 192, 256.
     * @return Randomly generated AES key.
     * @throws kmipcore::KmipException when RNG fails or size is unsupported.
     */
    static Key generate_aes(size_t size_bits);
    /**
     * @brief Parses a PEM payload into a KMIP key-like object.
     *
     * The parser recognizes X.509 certificate, public key, and private key
     * PEM blocks and maps them to the appropriate KMIP representation.
     *
     * @param pem PEM-formatted input.
     * @return Key mapped from the input PEM block.
     * @throws kmipcore::KmipException when parsing fails.
     */
    static Key from_PEM(const std::string &pem);
  };

}  // namespace kmipclient

#endif  // KMIPCLIENT_KEY_HPP
