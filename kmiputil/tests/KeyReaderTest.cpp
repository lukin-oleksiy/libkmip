/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmiputil/KeyReader.hpp"

#include "TestErrors.hpp"
#include "TestPem.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/secure_memory.hpp"

#include <algorithm>
#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <tuple>
#include <vector>

namespace {

  using kmipclient::KeyType;
  using kmiputil::KeyReader;

  constexpr std::string_view kAes128Hex = "000102030405060708090a0b0c0d0e0f";

  void expect_aes(const kmipclient::Key &key, size_t bytes) {
    EXPECT_EQ(key.type(), KeyType::SYMMETRIC_KEY);
    EXPECT_EQ(key.value().size(), bytes);
    EXPECT_EQ(
        key.algorithm(), kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_AES
    );
    EXPECT_EQ(key.crypto_length(), static_cast<int32_t>(bytes * 8));
    EXPECT_EQ(
        static_cast<uint32_t>(key.usage_mask()),
        static_cast<uint32_t>(
            kmipcore::KMIP_CRYPTOMASK_ENCRYPT |
            kmipcore::KMIP_CRYPTOMASK_DECRYPT
        )
    );
  }

  TEST(KeyReaderTest, AesFromHexOfEachSize) {
    expect_aes(KeyReader::aes_from_hex(kAes128Hex), 16);
    expect_aes(KeyReader::aes_from_hex(std::string(48, 'a')), 24);
    expect_aes(KeyReader::aes_from_hex(std::string(64, 'F')), 32);
  }

  TEST(KeyReaderTest, AesFromHexKeepsTheBytes) {
    const auto key = KeyReader::aes_from_hex(kAes128Hex);
    for (size_t i = 0; i < key.value().size(); ++i) {
      EXPECT_EQ(key.value()[i], i);
    }
  }

  TEST(KeyReaderTest, AesRejectsWrongLengthOrBadInput) {
    EXPECT_THROW(
        (void) KeyReader::aes_from_hex("000102"), kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyReader::aes_from_hex(std::string(32, 'g')),
        kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyReader::aes_from_value(std::vector<unsigned char>(17)),
        kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyReader::aes_from_value(std::vector<unsigned char>{}),
        kmipcore::KmipException
    );
  }

  TEST(KeyReaderTest, AesFromBase64AndValueAgree) {
    const std::vector<unsigned char> raw(32, 0x5a);
    const auto from_value = KeyReader::aes_from_value(raw);
    const auto from_b64 = KeyReader::aes_from_base64(
        "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo="
    );
    expect_aes(from_value, 32);
    EXPECT_EQ(from_value.value(), raw);
    EXPECT_EQ(from_b64.value(), raw);
  }

  TEST(KeyReaderTest, AesFromValueTakesSecureBytes) {
    const kmipcore::secure_bytes raw(16, 0x11);
    EXPECT_EQ(KeyReader::aes_from_value(raw).value(), raw);
  }

  TEST(KeyReaderTest, PemCertificate) {
    const auto key = KeyReader::from_PEM(kmiputil_test::kCertificate);
    EXPECT_EQ(key->type(), KeyType::CERTIFICATE);
    EXPECT_FALSE(key->value().empty());
    EXPECT_EQ(
        key->attribute_value(kmipclient::KMIP_ATTR_NAME_NAME), "certificate"
    );
  }

  TEST(KeyReaderTest, PemPrivateKeyInBothFormats) {
    const auto pkcs8 = KeyReader::from_PEM(kmiputil_test::kEcPrivateKeyPkcs8);
    const auto traditional =
        KeyReader::from_PEM(kmiputil_test::kEcPrivateKeyTraditional);
    EXPECT_EQ(pkcs8->type(), KeyType::PRIVATE_KEY);
    EXPECT_EQ(traditional->type(), KeyType::PRIVATE_KEY);
    EXPECT_EQ(pkcs8->value(), traditional->value());
    EXPECT_EQ(
        pkcs8->attribute_value(kmipclient::KMIP_ATTR_NAME_NAME), "private_key"
    );
  }

  // A PrivateKey is registered with Key Format Type PKCS#8, so that is what
  // the value must hold, whichever PEM form it was read from.
  TEST(KeyReaderTest, PemPrivateKeyValueIsPkcs8) {
    for (const auto pem :
         {kmiputil_test::kEcPrivateKeyPkcs8,
          kmiputil_test::kEcPrivateKeyTraditional}) {
      const auto key = KeyReader::from_PEM(pem);
      const kmipcore::secure_bytes &der = key->value();
      const unsigned char *p = der.data();
      PKCS8_PRIV_KEY_INFO *p8 =
          d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, static_cast<long>(der.size()));
      EXPECT_NE(p8, nullptr);
      EXPECT_EQ(p, der.data() + der.size());
      PKCS8_PRIV_KEY_INFO_free(p8);
    }
  }

  // Without these, registering the key would send the DER encoding's size
  // as its Cryptographic Length.
  TEST(KeyReaderTest, PemKeysCarryAlgorithmAndLength) {
    for (const auto pem :
         {kmiputil_test::kEcPrivateKeyPkcs8,
          kmiputil_test::kEcPublicKey,
          kmiputil_test::kCertificate}) {
      const auto key = KeyReader::from_PEM(pem);
      EXPECT_EQ(
          key->algorithm(),
          kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_EC
      );
      EXPECT_EQ(key->attributes().crypto_length(), 256);
    }
  }

  // KMIP has no Cryptographic Algorithm for X25519, and a length without an
  // algorithm is not allowed (KMIP 1.4 §2.1.3 Table 7): neither is set.
  TEST(KeyReaderTest, PemKeyWithoutKmipAlgorithmGetsNeither) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    ASSERT_NE(ctx, nullptr);
    EVP_PKEY *pkey = nullptr;
    ASSERT_EQ(EVP_PKEY_keygen_init(ctx), 1);
    ASSERT_EQ(EVP_PKEY_keygen(ctx, &pkey), 1);
    EVP_PKEY_CTX_free(ctx);
    BIO *bio = BIO_new(BIO_s_mem());
    ASSERT_EQ(
        PEM_write_bio_PrivateKey(
            bio, pkey, nullptr, nullptr, 0, nullptr, nullptr
        ),
        1
    );
    EVP_PKEY_free(pkey);
    char *data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    const std::string pem(data, static_cast<size_t>(len));
    BIO_free(bio);

    const auto key = KeyReader::from_PEM(pem);
    EXPECT_EQ(key->type(), KeyType::PRIVATE_KEY);
    EXPECT_EQ(
        key->algorithm(),
        kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_UNSET
    );
    EXPECT_FALSE(key->attributes().crypto_length().has_value());
  }

  // KMIP's Cryptographic Length is the key material's size in bits (1.4
  // §3.5): 32 bytes for Ed25519, 57 for Ed448. Not EVP_PKEY_bits, which
  // reports X25519's 253 for Ed25519 on OpenSSL 1.1.1.
  TEST(KeyReaderTest, PemEdwardsKeysCarryKeyMaterialLength) {
    for (const auto &[evp_type, algorithm, bits] :
         {std::tuple{
              EVP_PKEY_ED25519,
              kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_ED25519,
              256
          },
          std::tuple{
              EVP_PKEY_ED448,
              kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_ED448,
              456
          }}) {
      EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(evp_type, nullptr);
      ASSERT_NE(ctx, nullptr);
      EVP_PKEY *pkey = nullptr;
      ASSERT_EQ(EVP_PKEY_keygen_init(ctx), 1);
      ASSERT_EQ(EVP_PKEY_keygen(ctx, &pkey), 1);
      EVP_PKEY_CTX_free(ctx);
      BIO *bio = BIO_new(BIO_s_mem());
      ASSERT_EQ(PEM_write_bio_PUBKEY(bio, pkey), 1);
      EVP_PKEY_free(pkey);
      char *data = nullptr;
      const long len = BIO_get_mem_data(bio, &data);
      const std::string pem(data, static_cast<size_t>(len));
      BIO_free(bio);

      const auto key = KeyReader::from_PEM(pem);
      EXPECT_EQ(key->algorithm(), algorithm);
      EXPECT_EQ(key->attributes().crypto_length(), bits);
    }
  }

  // A certificate whose public key OpenSSL cannot decode is still read,
  // with no algorithm or length, and the failed decode leaves no error.
  TEST(KeyReaderTest, PemCertificateWithUndecodableKey) {
    BIO *in = BIO_new_mem_buf(
        kmiputil_test::kCertificate.data(),
        static_cast<int>(kmiputil_test::kCertificate.size())
    );
    X509 *cert = PEM_read_bio_X509(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    ASSERT_NE(cert, nullptr);
    unsigned char *der = nullptr;
    const int der_len = i2d_X509(cert, &der);
    X509_free(cert);
    ASSERT_GT(der_len, 0);
    std::vector<unsigned char> bytes(der, der + der_len);
    OPENSSL_free(der);
    // id-ecPublicKey (1.2.840.10045.2.1) -> 1.2.840.10045.2.99, unknown.
    const std::vector<unsigned char> ec_public_key_oid{
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
    };
    const auto oid = std::search(
        bytes.begin(),
        bytes.end(),
        ec_public_key_oid.begin(),
        ec_public_key_oid.end()
    );
    ASSERT_NE(oid, bytes.end());
    *(oid + ec_public_key_oid.size() - 1) = 0x63;
    BIO *out = BIO_new(BIO_s_mem());
    ASSERT_GT(  // bytes written
        PEM_write_bio(
            out,
            "CERTIFICATE",
            "",
            bytes.data(),
            static_cast<long>(bytes.size())
        ),
        0
    );
    char *data = nullptr;
    const long len = BIO_get_mem_data(out, &data);
    const std::string pem(data, static_cast<size_t>(len));
    BIO_free(out);

    ERR_clear_error();
    const auto key = KeyReader::from_PEM(pem);
    EXPECT_EQ(key->type(), KeyType::CERTIFICATE);
    EXPECT_EQ(
        key->algorithm(),
        kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_UNSET
    );
    EXPECT_FALSE(key->attributes().crypto_length().has_value());
    EXPECT_EQ(ERR_peek_error(), 0u);
  }

  TEST(KeyReaderTest, PemPublicKey) {
    const auto key = KeyReader::from_PEM(kmiputil_test::kEcPublicKey);
    EXPECT_EQ(key->type(), KeyType::PUBLIC_KEY);
    EXPECT_FALSE(key->value().empty());
    EXPECT_EQ(
        key->attribute_value(kmipclient::KMIP_ATTR_NAME_NAME), "public_key"
    );
  }

  TEST(KeyReaderTest, PemSymmetricKeyText) {
    const auto key = KeyReader::from_PEM(
        "-----BEGIN SYMMETRIC KEY-----\n"
        "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=\n"
        "-----END SYMMETRIC KEY-----\n"
    );
    expect_aes(*key, 32);
    EXPECT_EQ(key->value(), std::vector<unsigned char>(32, 0x5a));
  }

  TEST(KeyReaderTest, PemSymmetricKeyWithCrlfAndTrailingSpaces) {
    const auto key = KeyReader::from_PEM(
        "-----BEGIN SYMMETRIC KEY----- \r\n"
        "WlpaWlpaWlpaWlpaWlpaWlpa\r\n"
        "WlpaWlpaWlpaWlpaWlo=\t\r\n"
        "-----END SYMMETRIC KEY-----\r\n"
    );
    expect_aes(*key, 32);
    EXPECT_EQ(key->value(), std::vector<unsigned char>(32, 0x5a));
  }

  // Truncated input must not yield a key, even if the body decodes.
  TEST(KeyReaderTest, PemSymmetricKeyWithoutEndIsRejected) {
    EXPECT_THROW(
        (void) KeyReader::from_PEM(
            "-----BEGIN SYMMETRIC KEY-----\n"
            "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=\n"
        ),
        kmipcore::KmipException
    );
  }

  TEST(KeyReaderTest, AesFromBase64RejectsInvalidCharacters) {
    // 16 bytes once the invalid characters are dropped, which the
    // kmipclient factory this replaced used to accept.
    EXPECT_THROW(
        (void) KeyReader::aes_from_base64("!!!!AAAAAAAAAAAAAAAAAAAAAA==??"),
        kmipcore::KmipException
    );
  }

  // A non-SYMMETRIC-KEY label must not be reinterpreted as an AES key, even
  // when its body happens to decode to a valid AES key length.
  TEST(KeyReaderTest, PemWrongLabelIsNotReadAsSymmetricKey) {
    EXPECT_THROW(
        (void) KeyReader::from_PEM(
            "-----BEGIN NOT A KEY-----\n"
            "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=\n"
            "-----END NOT A KEY-----\n"
        ),
        kmipcore::KmipException
    );
  }

  // Must fail rather than prompt on the terminal for the passphrase.
  TEST(KeyReaderTest, PemEncryptedPrivateKeyIsRejected) {
    EXPECT_THROW(
        (void) KeyReader::from_PEM(kmiputil_test::kEncryptedPrivateKey),
        kmipcore::KmipException
    );
  }

  TEST(KeyReaderTest, PemGarbageIsRejected) {
    EXPECT_THROW((void) KeyReader::from_PEM(""), kmipcore::KmipException);
    EXPECT_THROW(
        (void) KeyReader::from_PEM("not a pem"), kmipcore::KmipException
    );
  }

  // Failed parse attempts must not leave errors behind for later TLS calls.
  TEST(KeyReaderTest, PemLeavesOpenSSLErrorQueueEmpty) {
    ERR_clear_error();
    (void) KeyReader::from_PEM(kmiputil_test::kEcPublicKey);
    EXPECT_EQ(ERR_peek_error(), 0u);
  }

  // An empty view may have no data pointer; it must fail like any other
  // unsupported input, without leaving OpenSSL errors behind.
  TEST(KeyReaderTest, PemEmptyViewIsRejectedCleanly) {
    ERR_clear_error();
    try {
      (void) KeyReader::from_PEM(std::string_view{});
      ADD_FAILURE() << "expected a KmipException";
    } catch (const kmipcore::KmipException &e) {
      EXPECT_EQ(e.code().value(), kmipcore::KMIP_NOT_IMPLEMENTED);
    }
    EXPECT_EQ(ERR_peek_error(), 0u);
  }

  // Errors the caller left on the queue are theirs: from_PEM drops only
  // its own, on success and on failure.
  TEST(KeyReaderTest, PemKeepsTheCallersOpenSSLErrors) {
    const unsigned long callers = kmiputil_test::push_callers_openssl_error();
    ASSERT_NE(callers, 0u);
    (void) KeyReader::from_PEM(kmiputil_test::kEcPublicKey);
    EXPECT_EQ(ERR_peek_last_error(), callers);
    EXPECT_THROW(
        (void) KeyReader::from_PEM("not a pem"), kmipcore::KmipException
    );
    EXPECT_EQ(ERR_peek_last_error(), callers);
    ERR_clear_error();
  }

}  // namespace
