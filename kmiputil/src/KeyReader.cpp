/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmiputil/KeyReader.hpp"

#include "AesKey.hpp"
#include "Encoding.hpp"
#include "OpenSSLUtils.hpp"
#include "kmipclient/PrivateKey.hpp"
#include "kmipclient/PublicKey.hpp"
#include "kmipclient/X509Certificate.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/secure_memory.hpp"

#include <climits>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string>

namespace kmiputil {

  namespace {

    // Without a callback OpenSSL prompts on the terminal for the passphrase of
    // an encrypted key. A library must not do that, so refuse instead.
    int no_passphrase(char *, int, int, void *) {
      return -1;
    }

    // KMIP algorithm of an OpenSSL key, or UNSET for a type KMIP has no value
    // for (e.g. X25519). Ed25519 and Ed448 exist only in KMIP 2.0 (2.0
    // §11.12); Register leaves them out of KMIP 1.x requests.
    kmipclient::cryptographic_algorithm kmip_algorithm(const EVP_PKEY *pkey) {
      using algorithm = kmipclient::cryptographic_algorithm;
      switch (EVP_PKEY_base_id(pkey)) {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA_PSS:
          return algorithm::KMIP_CRYPTOALG_RSA;
        case EVP_PKEY_DSA:
          return algorithm::KMIP_CRYPTOALG_DSA;
        case EVP_PKEY_DH:
          return algorithm::KMIP_CRYPTOALG_DH;
        case EVP_PKEY_EC:
          return algorithm::KMIP_CRYPTOALG_EC;
        case EVP_PKEY_ED25519:
          return algorithm::KMIP_CRYPTOALG_ED25519;
        case EVP_PKEY_ED448:
          return algorithm::KMIP_CRYPTOALG_ED448;
        default:
          return algorithm::KMIP_CRYPTOALG_UNSET;
      }
    }

    // Cryptographic Length of an OpenSSL key: "the length in bits of the
    // clear-text cryptographic key material" (1.4 §3.5, 2.0 §4.15), or 0 if
    // unknown. EVP_PKEY_bits gives the modulus size for RSA and the field
    // size for EC, but not the key size of Ed25519 on OpenSSL 1.1.1, where it
    // reports 253 (X25519's), so the Edwards keys use their RFC 8032 sizes.
    int key_length_bits(const EVP_PKEY *pkey) {
      switch (EVP_PKEY_base_id(pkey)) {
        case EVP_PKEY_ED25519:
          return 256;  // 32-byte keys, RFC 8032 §5.1.5
        case EVP_PKEY_ED448:
          return 456;  // 57-byte keys, RFC 8032 §5.2.5
        default:
          return EVP_PKEY_bits(pkey);
      }
    }

    // Name plus the Cryptographic Algorithm and Length (KMIP 1.4 §3.4, §3.5)
    // sent on registration. KMIP sends the two together or not at all (1.4
    // §2.1.3 Table 7), so both are set or neither: for a key type KMIP has
    // no algorithm for (e.g. X25519), a null pkey (a certificate whose key
    // OpenSSL cannot decode), or an unknown size. Either way the key
    // encoding still carries them.
    kmipcore::Attributes
        key_attributes(const EVP_PKEY *pkey, const char *name) {
      kmipcore::Attributes attrs;
      attrs.set(kmipclient::KMIP_ATTR_NAME_NAME, name);
      if (!pkey) {
        return attrs;
      }
      const auto algorithm = kmip_algorithm(pkey);
      const int bits = key_length_bits(pkey);
      if (algorithm !=
              kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_UNSET &&
          bits > 0) {
        attrs.set_algorithm(algorithm).set_crypto_length(bits);
      }
      return attrs;
    }

    std::unique_ptr<kmipclient::Key> try_parse_x509_certificate(BIO *bio) {
      X509 *cert = PEM_read_bio_X509(bio, nullptr, no_passphrase, nullptr);
      if (!cert) {
        return nullptr;
      }

      unsigned char *der = nullptr;
      const int len = i2d_X509(cert, &der);
      const detail::DerBuffer buf(der, len);
      kmipcore::Attributes attrs =
          key_attributes(X509_get0_pubkey(cert), "certificate");
      X509_free(cert);
      if (!buf) {
        return nullptr;
      }

      return std::make_unique<kmipclient::X509Certificate>(
          buf.span(), std::move(attrs)
      );
    }

    std::unique_ptr<kmipclient::Key> try_parse_private_key(BIO *bio) {
      EVP_PKEY *pkey =
          PEM_read_bio_PrivateKey(bio, nullptr, no_passphrase, nullptr);
      if (!pkey) {
        return nullptr;
      }

      // Stored as PKCS#8 PrivateKeyInfo, the Key Format Type a PrivateKey is
      // registered with. (i2d_PrivateKey would give the per-algorithm
      // format instead: PKCS#1 for RSA, SEC1 for EC.)
      PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(pkey);
      unsigned char *der = nullptr;
      const int len = p8 ? i2d_PKCS8_PRIV_KEY_INFO(p8, &der) : 0;
      const detail::DerBuffer buf(der, len);
      PKCS8_PRIV_KEY_INFO_free(p8);  // clears the key material it holds
      kmipcore::Attributes attrs = key_attributes(pkey, "private_key");
      EVP_PKEY_free(pkey);
      if (!buf) {
        return nullptr;
      }

      return std::make_unique<kmipclient::PrivateKey>(
          buf.span(), std::move(attrs)
      );
    }

    std::unique_ptr<kmipclient::Key> try_parse_public_key(BIO *bio) {
      EVP_PKEY *pkey =
          PEM_read_bio_PUBKEY(bio, nullptr, no_passphrase, nullptr);
      if (!pkey) {
        return nullptr;
      }

      unsigned char *der = nullptr;
      const int len = i2d_PUBKEY(pkey, &der);
      const detail::DerBuffer buf(der, len);
      kmipcore::Attributes attrs = key_attributes(pkey, "public_key");
      EVP_PKEY_free(pkey);
      if (!buf) {
        return nullptr;
      }

      return std::make_unique<kmipclient::PublicKey>(
          buf.span(), std::move(attrs)
      );
    }

    // Label matches what KeyWriter::to_PEM writes for a symmetric key; there
    // is no standard PEM type for raw key material, so any other label (an
    // encrypted private key, say) must not be reinterpreted as an AES key
    // just because its body happens to decode to an AES key length.
    constexpr std::string_view kSymmetricKeyBegin =
        "-----BEGIN SYMMETRIC KEY-----";
    constexpr std::string_view kSymmetricKeyEnd = "-----END SYMMETRIC KEY-----";

    // Drops a trailing '\r' (CRLF line endings) and any trailing spaces or
    // tabs, as OpenSSL does for the other PEM types.
    std::string_view trim_trailing_whitespace(std::string_view line) {
      const size_t end = line.find_last_not_of(" \t\r");
      return end == std::string_view::npos ? std::string_view{}
                                           : line.substr(0, end + 1);
    }

    std::unique_ptr<kmipclient::Key>
        try_parse_aes_from_pem_text(std::string_view pem) {
      kmipcore::secure_string b64;
      bool in_pem = false;
      bool complete = false;
      while (!pem.empty()) {
        const size_t eol = pem.find('\n');
        const std::string_view line =
            trim_trailing_whitespace(pem.substr(0, eol));
        pem.remove_prefix(eol == std::string_view::npos ? pem.size() : eol + 1);

        if (!in_pem) {
          in_pem = line == kSymmetricKeyBegin;
          continue;
        }
        if (line == kSymmetricKeyEnd) {
          complete = true;
          break;
        }
        b64.append(line);
      }

      // A missing END line means truncated input, not a usable key.
      if (!complete || b64.empty()) {
        return nullptr;
      }

      try {
        return std::make_unique<kmipclient::SymmetricKey>(
            KeyReader::aes_from_base64(b64)
        );
      } catch (const kmipcore::KmipException &) {
        return nullptr;
      }
    }

  }  // namespace

  kmipclient::SymmetricKey KeyReader::aes_from_hex(std::string_view hex) {
    return detail::make_aes_key(encoding::from_hex(hex));
  }

  kmipclient::SymmetricKey KeyReader::aes_from_base64(std::string_view base64) {
    return detail::make_aes_key(encoding::from_base64(base64));
  }

  kmipclient::SymmetricKey
      KeyReader::aes_from_value(std::span<const unsigned char> value) {
    return detail::make_aes_key(value);
  }

  std::unique_ptr<kmipclient::Key> KeyReader::from_PEM(std::string_view pem) {
    const auto unsupported = [] {
      return kmipcore::KmipException(
          kmipcore::KMIP_NOT_IMPLEMENTED,
          "Unsupported PEM format or not implemented"
      );
    };
    // An empty view may have no data pointer, which BIO_new_mem_buf rejects
    // with an error of its own; there is nothing to parse anyway.
    if (pem.empty()) {
      throw unsupported();
    }
    if (pem.size() > INT_MAX) {
      throw kmipcore::KmipException("PEM data is too large");
    }
    // Failed attempts push errors; the scope drops them (and any of a
    // successful one) so later TLS calls do not see them, while the
    // caller's own pending errors stay (best effort, see OpenSslErrorScope).
    detail::OpenSslErrorScope errors;
    const detail::BioPtr bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))
    );
    if (!bio) {
      throw kmipcore::KmipException("Failed to create BIO for PEM data");
    }

    for (auto parse :
         {try_parse_x509_certificate,
          try_parse_private_key,
          try_parse_public_key}) {
      if (auto key = parse(bio.get())) {
        return key;
      }
      errors.reset();
      (void) BIO_reset(bio.get());
    }

    if (auto key = try_parse_aes_from_pem_text(pem)) {
      return key;
    }
    throw unsupported();
  }

}  // namespace kmiputil
