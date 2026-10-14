/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_TEST_KEYS_HPP
#define KMIPCLIENT_TEST_KEYS_HPP

#include "kmipclient/SymmetricKey.hpp"
#include "kmipclient/types.hpp"

#include <cstdint>
#include <span>

namespace kmipclient_test {

  /** An AES key with the attributes registration needs, built here so
   * kmipclient's tests do not depend on kmiputil. */
  inline kmipclient::SymmetricKey
      aes_key(std::span<const unsigned char> value) {
    kmipcore::Attributes attrs;
    attrs.set_algorithm(kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_AES)
        .set_crypto_length(static_cast<int32_t>(value.size() * 8))
        .set_usage_mask(
            static_cast<kmipclient::cryptographic_usage_mask>(
                kmipcore::KMIP_CRYPTOMASK_ENCRYPT |
                kmipcore::KMIP_CRYPTOMASK_DECRYPT
            )
        );
    return kmipclient::SymmetricKey(value, std::move(attrs));
  }

}  // namespace kmipclient_test

#endif  // KMIPCLIENT_TEST_KEYS_HPP
