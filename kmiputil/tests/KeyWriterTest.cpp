/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmiputil/KeyWriter.hpp"

#include "TestErrors.hpp"
#include "TestPem.hpp"
#include "kmipclient/PrivateKey.hpp"
#include "kmipclient/PublicKey.hpp"
#include "kmipclient/X509Certificate.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmiputil/KeyReader.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string>
#include <vector>

namespace {

  using kmipclient::KeyType;
  using kmiputil::KeyReader;
  using kmiputil::KeyWriter;

  std::string as_string(const kmipcore::secure_string &s) {
    return {s.begin(), s.end()};
  }

  void expect_pem_round_trip(const kmipclient::Key &key, const char *label) {
    const std::string pem = as_string(KeyWriter::to_PEM(key));
    EXPECT_TRUE(pem.starts_with(std::string("-----BEGIN ") + label + "-----\n"))
        << pem;
    const auto back = KeyReader::from_PEM(pem);
    EXPECT_EQ(back->type(), key.type());
    EXPECT_EQ(back->value(), key.value());
  }

  TEST(KeyWriterTest, HexAndBase64) {
    const auto key =
        KeyReader::aes_from_hex("000102030405060708090a0b0c0d0e0f");
    EXPECT_EQ(KeyWriter::to_hex(key), "000102030405060708090a0b0c0d0e0f");
    EXPECT_EQ(KeyWriter::to_base64(key), "AAECAwQFBgcICQoLDA0ODw==");
    EXPECT_EQ(
        KeyReader::aes_from_base64(as_string(KeyWriter::to_base64(key)))
            .value(),
        key.value()
    );
  }

  TEST(KeyWriterTest, CertificatePemMatchesInput) {
    const auto key = KeyReader::from_PEM(kmiputil_test::kCertificate);
    EXPECT_EQ(as_string(KeyWriter::to_PEM(*key)), kmiputil_test::kCertificate);
    expect_pem_round_trip(*key, "CERTIFICATE");
  }

  TEST(KeyWriterTest, PublicKeyPemMatchesInput) {
    const auto key = KeyReader::from_PEM(kmiputil_test::kEcPublicKey);
    EXPECT_EQ(as_string(KeyWriter::to_PEM(*key)), kmiputil_test::kEcPublicKey);
    expect_pem_round_trip(*key, "PUBLIC KEY");
  }

  TEST(KeyWriterTest, PrivateKeyIsWrittenAsPkcs8) {
    const auto key =
        KeyReader::from_PEM(kmiputil_test::kEcPrivateKeyTraditional);
    expect_pem_round_trip(*key, "PRIVATE KEY");
  }

  TEST(KeyWriterTest, SymmetricKeyPemIsOneLine) {
    // 32 bytes encode to 44 Base64 characters: a single line.
    const auto key =
        KeyReader::aes_from_value(std::vector<unsigned char>(32, 1));
    const std::string pem = as_string(KeyWriter::to_PEM(key));
    EXPECT_EQ(
        pem,
        "-----BEGIN SYMMETRIC KEY-----\n"
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"
        "-----END SYMMETRIC KEY-----\n"
    );
    expect_pem_round_trip(key, "SYMMETRIC KEY");
  }

  // from_PEM reads SYMMETRIC KEY text back as AES, so writing any other
  // symmetric key would come back as AES (16 or 32 bytes) or not at all.
  TEST(KeyWriterTest, SymmetricKeyPemRequiresAes) {
    auto key_with = [](size_t size, kmipclient::cryptographic_algorithm alg) {
      kmipcore::Attributes attrs;
      if (alg != kmipclient::cryptographic_algorithm::KMIP_CRYPTOALG_UNSET) {
        attrs.set_algorithm(alg);
      }
      return kmipclient::SymmetricKey(
          std::vector<unsigned char>(size, 2), std::move(attrs)
      );
    };
    using alg = kmipclient::cryptographic_algorithm;
    for (const auto &key :
         {key_with(32, alg::KMIP_CRYPTOALG_HMAC_SHA256),
          key_with(20, alg::KMIP_CRYPTOALG_HMAC_SHA256),
          key_with(32, alg::KMIP_CRYPTOALG_UNSET),
          key_with(20, alg::KMIP_CRYPTOALG_AES),
          key_with(64, alg::KMIP_CRYPTOALG_AES)}) {
      EXPECT_THROW((void) KeyWriter::to_PEM(key), kmipcore::KmipException)
          << key.value().size() << " bytes";
    }
    for (const size_t size : {16u, 24u, 32u}) {
      expect_pem_round_trip(
          key_with(size, alg::KMIP_CRYPTOALG_AES), "SYMMETRIC KEY"
      );
    }
  }

  // Servers return RSA public keys as bare PKCS#1 RSAPublicKey when asked for
  // that key format; the writer turns them into SubjectPublicKeyInfo.
  TEST(KeyWriterTest, RsaPkcs1PublicKey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    ASSERT_NE(ctx, nullptr);
    EVP_PKEY *raw = nullptr;
    ASSERT_EQ(EVP_PKEY_keygen_init(ctx), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048), 1);
    ASSERT_EQ(EVP_PKEY_keygen(ctx, &raw), 1);
    EVP_PKEY_CTX_free(ctx);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        raw, EVP_PKEY_free
    );

    // i2d_* allocate the output; copy it out and free it.
    auto take_der = [](unsigned char *der, int len) {
      std::vector<unsigned char> v(der, der + len);
      OPENSSL_free(der);
      return v;
    };
    unsigned char *der = nullptr;
    int len = i2d_PublicKey(pkey.get(), &der);
    ASSERT_GT(len, 0);
    const auto pkcs1 = take_der(der, len);
    der = nullptr;
    len = i2d_PUBKEY(pkey.get(), &der);
    ASSERT_GT(len, 0);
    const auto spki = take_der(der, len);

    const std::string pem =
        as_string(KeyWriter::to_PEM(kmipclient::PublicKey(pkcs1)));
    EXPECT_TRUE(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    EXPECT_EQ(KeyReader::from_PEM(pem)->value(), spki);
  }

  TEST(KeyWriterTest, KeepsTheCallersOpenSSLErrors) {
    const auto key = KeyReader::from_PEM(kmiputil_test::kEcPublicKey);
    const unsigned long callers = kmiputil_test::push_callers_openssl_error();
    ASSERT_NE(callers, 0u);
    (void) KeyWriter::to_PEM(*key);
    EXPECT_EQ(ERR_peek_last_error(), callers);
    const std::vector<unsigned char> junk{0x01, 0x02, 0x03};
    try {
      (void) KeyWriter::to_PEM(kmipclient::PublicKey(junk));
      ADD_FAILURE() << "expected a KmipException";
    } catch (const kmipcore::KmipException &e) {
      // The message reports this call's error, not the caller's.
      char callers_text[256];
      ERR_error_string_n(callers, callers_text, sizeof(callers_text));
      EXPECT_EQ(std::string(e.what()).find(callers_text), std::string::npos)
          << e.what();
    }
    EXPECT_EQ(ERR_peek_last_error(), callers);
    ERR_clear_error();
  }

  // This call's error is reported even when the caller has one with the
  // same code pending: both are a failed DER parse ("nested asn1 error").
  TEST(KeyWriterTest, ReportsItsErrorWhenTheCallersHasTheSameCode) {
    const unsigned long callers = kmiputil_test::push_callers_openssl_error();
    ASSERT_NE(callers, 0u);
    const std::vector<unsigned char> junk{0x01, 0x02, 0x03};
    try {
      (void) KeyWriter::to_PEM(kmipclient::PrivateKey(junk));
      ADD_FAILURE() << "expected a KmipException";
    } catch (const kmipcore::KmipException &e) {
      EXPECT_EQ(std::string(e.what()).find("unknown error"), std::string::npos)
          << e.what();
    }
    // Not checked here: that the caller's error survives. On OpenSSL 3.0 a
    // failed private-key parse pushes more errors than the queue holds, which
    // overwrites it (see OpenSslErrorScope); KeepsTheCallersOpenSSLErrors
    // covers the paths where it does survive.
    ERR_clear_error();
  }

  TEST(KeyWriterTest, RejectsMaterialThatDoesNotMatchTheType) {
    const std::vector<unsigned char> junk{0x01, 0x02, 0x03};
    EXPECT_THROW(
        (void) KeyWriter::to_PEM(kmipclient::PrivateKey(junk)),
        kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyWriter::to_PEM(kmipclient::PublicKey(junk)),
        kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyWriter::to_PEM(kmipclient::X509Certificate(junk)),
        kmipcore::KmipException
    );
    EXPECT_THROW(
        (void) KeyWriter::to_PEM(
            kmipclient::SymmetricKey(std::vector<unsigned char>{})
        ),
        kmipcore::KmipException
    );
  }

  TEST(KeyWriterTest, RejectsTrailingBytesAfterCertificate) {
    const auto cert = KeyReader::from_PEM(kmiputil_test::kCertificate);
    std::vector<unsigned char> der(cert->value().begin(), cert->value().end());
    der.push_back(0);
    EXPECT_THROW(
        (void) KeyWriter::to_PEM(kmipclient::X509Certificate(der)),
        kmipcore::KmipException
    );
  }

}  // namespace
