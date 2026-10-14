/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPUTIL_OPENSSL_UTILS_HPP
#define KMIPUTIL_OPENSSL_UTILS_HPP

#include <memory>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <span>
#include <string>

namespace kmiputil::detail {

  struct BioDeleter {
    void operator()(BIO *bio) const noexcept { BIO_free(bio); }
  };
  using BioPtr = std::unique_ptr<BIO, BioDeleter>;

  /**
   * Owns a DER buffer allocated by an OpenSSL `i2d_*` call and clears +
   * frees it on destruction, including when an exception unwinds past it
   * while the buffer still holds key material.
   */
  class DerBuffer {
  public:
    // der/len as returned by i2d_*: der may be non-null with len <= 0 on
    // failure, so operator bool() checks both.
    DerBuffer(unsigned char *der, int len) noexcept : der_(der), len_(len) {}
    DerBuffer(const DerBuffer &) = delete;
    DerBuffer &operator=(const DerBuffer &) = delete;
    ~DerBuffer() {
      OPENSSL_clear_free(der_, len_ > 0 ? static_cast<size_t>(len_) : 0);
    }

    explicit operator bool() const noexcept { return len_ > 0; }

    std::span<const unsigned char> span() const noexcept {
      return {der_, static_cast<size_t>(len_)};
    }

  private:
    unsigned char *der_;
    int len_;
  };

  /**
   * Confines the OpenSSL errors of one library call to that call: the
   * caller's own pending errors are left as they were, and none of ours
   * remain for later calls (e.g. TLS) to pick up.
   *
   * Marks the thread's error queue and pushes a placeholder error above the
   * mark; destruction drops everything down to the mark. The placeholder
   * keeps the mark off the top of the queue while OpenSSL runs: OpenSSL
   * 1.1.1 marks an entry with a flag, not a count, so a mark OpenSSL sets
   * and pops itself on that same entry (d2i_X509_PUBKEY does) would clear
   * ours, and our pop would then empty the whole queue. The placeholder
   * also tells last_error() whether anything was pushed since.
   *
   * Keeping the caller's errors is best effort: the queue is a ring of
   * ERR_NUM_ERRORS (16) entries, and once OpenSSL pushes more than that its
   * newest entries overwrite the oldest, the caller's errors and our mark
   * among them, so the pop at the end empties the queue. OpenSSL 3.0 pushes
   * that many on a failed private-key parse (d2i_AutoPrivateKey, seen with
   * 3.0.13; 1.1.1 and 3.5 do not). None of ours are left behind either way.
   */
  class OpenSslErrorScope {
  public:
    OpenSslErrorScope() noexcept { mark(); }
    OpenSslErrorScope(const OpenSslErrorScope &) = delete;
    OpenSslErrorScope &operator=(const OpenSslErrorScope &) = delete;
    ~OpenSslErrorScope() { ERR_pop_to_mark(); }

    /** Drops the errors pushed so far, e.g. after a failed parse attempt. */
    void reset() noexcept {
      ERR_pop_to_mark();
      mark();
    }

    /** Text of the latest error pushed in this scope, never the caller's. */
    [[nodiscard]] std::string last_error() const {
      const unsigned long err = ERR_peek_last_error();
      if (err == 0 || is_placeholder(err)) {
        return "unknown error";
      }
      char buf[256];
      ERR_error_string_n(err, buf, sizeof(buf));
      return buf;
    }

  private:
    // ERR_LIB_USER is for applications; OpenSSL never raises it itself.
    static constexpr int kPlaceholderReason = 0xA5A;

    static bool is_placeholder(unsigned long err) noexcept {
      return ERR_GET_LIB(err) == ERR_LIB_USER &&
             ERR_GET_REASON(err) == kPlaceholderReason;
    }

    static void mark() noexcept {
      ERR_set_mark();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
      ERR_raise(ERR_LIB_USER, kPlaceholderReason);
#else
      ERR_put_error(ERR_LIB_USER, 0, kPlaceholderReason, __FILE__, __LINE__);
#endif
    }
  };

}  // namespace kmiputil::detail

#endif  // KMIPUTIL_OPENSSL_UTILS_HPP
