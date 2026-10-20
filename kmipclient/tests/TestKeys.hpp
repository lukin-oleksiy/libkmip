/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_TEST_KEYS_HPP
#define KMIPCLIENT_TEST_KEYS_HPP

// Keys for kmipclient's tests, built here so the tests do not depend on
// kmiputil (kmiputil -> kmipclient -> kmipcore).

#include "kmipclient/PrivateKey.hpp"
#include "kmipclient/PublicKey.hpp"
#include "kmipclient/SymmetricKey.hpp"
#include "kmipclient/types.hpp"

#include <cstdint>
#include <memory>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <span>
#include <stdexcept>
#include <vector>

namespace kmipclient_test {

  /** An AES key with the attributes registration needs. */
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

  struct KeyPair {
    kmipclient::PrivateKey private_key;
    kmipclient::PublicKey public_key;
  };

  /**
   * Generates an RSA-2048 (EVP_PKEY_RSA) or P-256 (EVP_PKEY_EC) key pair as
   * PKCS#8 and SubjectPublicKeyInfo DER, the formats Register declares by
   * default, with their algorithm and length set.
   */
  inline KeyPair generate_key_pair(int evp_type) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(evp_type, nullptr), EVP_PKEY_CTX_free
    );
    EVP_PKEY *raw = nullptr;
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
        (evp_type == EVP_PKEY_RSA &&
         EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) != 1) ||
        (evp_type == EVP_PKEY_EC && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                                        ctx.get(), NID_X9_62_prime256v1
                                    ) != 1) ||
        EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
      throw std::runtime_error("test key generation failed");
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        raw, EVP_PKEY_free
    );

    // i2d_* allocate the output; copy it out and free it.
    const auto take_der = [](unsigned char *der, int len) {
      if (len <= 0) {
        throw std::runtime_error("test key DER encoding failed");
      }
      std::vector<unsigned char> bytes(der, der + len);
      OPENSSL_clear_free(der, static_cast<size_t>(len));
      return bytes;
    };
    std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)>
        p8(EVP_PKEY2PKCS8(pkey.get()), PKCS8_PRIV_KEY_INFO_free);
    unsigned char *der = nullptr;
    // Encode before reading der: function arguments may be evaluated in
    // either order, so passing der alongside i2d_* can pass a null pointer.
    const int pkcs8_len = p8 ? i2d_PKCS8_PRIV_KEY_INFO(p8.get(), &der) : 0;
    const auto pkcs8 = take_der(der, pkcs8_len);
    der = nullptr;
    const int spki_len = i2d_PUBKEY(pkey.get(), &der);
    const auto spki = take_der(der, spki_len);

    kmipcore::Attributes attrs;
    attrs
        .set_algorithm(
            evp_type == EVP_PKEY_RSA
                ? kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_RSA
                : kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_EC
        )
        .set_crypto_length(EVP_PKEY_bits(pkey.get()));
    return {
        kmipclient::PrivateKey(pkcs8, attrs), kmipclient::PublicKey(spki, attrs)
    };
  }

}  // namespace kmipclient_test

#endif  // KMIPCLIENT_TEST_KEYS_HPP
