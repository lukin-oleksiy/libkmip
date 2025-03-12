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

#ifndef KMIPCORE_KEY_HPP
#define KMIPCORE_KEY_HPP

#include "kmipcore/types.hpp"

#include <utility>

namespace kmipcore {

  /** @brief Key object families represented by @ref Key. */
  enum KeyType { UNSET, SYMMETRIC_KEY, PUBLIC_KEY, PRIVATE_KEY, CERTIFICATE };

  /**
   * Minimal crypto key representation as KMIP spec sees it.
   * Contains key value, type, algorithm, usage mask, and attributes.
   * No factory methods — those belong in higher-level layers.
   */
  class Key {
  public:
    /**
     * @brief Constructs a KMIP key object.
     * @param value Raw key bytes.
     * @param k_type Key family.
     * @param algo Cryptographic algorithm.
     * @param usage_mask Cryptographic usage mask flags.
     * @param attributes Additional key attributes.
     */
    explicit Key(
        key_t value,
        KeyType k_type,
        cryptographic_algorithm algo,
        cryptographic_usage_mask usage_mask,
        attributes_t attributes
    )
      : key_value(std::move(value)),
        key_type(k_type),
        key_attributes(std::move(attributes)),
        crypto_algorithm(algo),
        crypto_usage_mask(usage_mask) {};

    /** @brief Constructs an empty key object. */
    Key() = default;
    /** @brief Virtual destructor for subclass-safe cleanup. */
    virtual ~Key() = default;

    Key(const Key &) = default;
    Key &operator=(const Key &) = default;
    Key(Key &&) noexcept = default;
    Key &operator=(Key &&) noexcept = default;

    /** @brief Returns raw key bytes. */
    [[nodiscard]] const key_t &value() const noexcept { return key_value; };

    /** @brief Returns all attached key attributes. */
    [[nodiscard]] const attributes_t &attributes() const noexcept {
      return key_attributes;
    };

    /**
     * @brief Returns value of a required attribute.
     * @param name Attribute name.
     * @return Attribute value.
     * @throws std::out_of_range if attribute is absent.
     */
    [[nodiscard]] const std::string &
        attribute_value(const std::string &name) const {
      return key_attributes.at(name);
    };

    /** @brief Sets or replaces one attribute value. */
    void set_attribute(
        const std::string &name, const std::string &val
    ) noexcept {
      key_attributes[name] = val;
    };

    /** @brief Returns KMIP usage mask flags. */
    [[nodiscard]] cryptographic_usage_mask usage_mask() const noexcept {
      return crypto_usage_mask;
    }

    /** @brief Returns KMIP cryptographic algorithm. */
    [[nodiscard]] cryptographic_algorithm algorithm() const noexcept {
      return crypto_algorithm;
    };

    /** @brief Returns key family discriminator. */
    [[nodiscard]] KeyType type() const noexcept { return key_type; };

    /** @brief Returns key length in bytes. */
    [[nodiscard]] size_t size() const noexcept { return key_value.size(); }

  private:
    key_t key_value;
    KeyType key_type = UNSET;
    attributes_t key_attributes;
    cryptographic_algorithm crypto_algorithm =
        cryptographic_algorithm::KMIP_CRYPTOALG_UNSET;
    cryptographic_usage_mask crypto_usage_mask =
        cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET;
  };

}  // namespace kmipcore

#endif  // KMIPCORE_KEY_HPP
