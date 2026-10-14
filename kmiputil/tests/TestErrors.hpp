/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPUTIL_TEST_ERRORS_HPP
#define KMIPUTIL_TEST_ERRORS_HPP

#include <openssl/err.h>
#include <openssl/x509.h>

namespace kmiputil_test {

  /** Leaves an error of the caller's own on the thread's OpenSSL error queue
   * (a failed DER parse) and returns its code: kmiputil must not drop it. */
  inline unsigned long push_callers_openssl_error() {
    ERR_clear_error();
    const unsigned char junk[] = {0x00};
    const unsigned char *p = junk;
    (void) d2i_X509(nullptr, &p, sizeof(junk));
    return ERR_peek_last_error();
  }

}  // namespace kmiputil_test

#endif  // KMIPUTIL_TEST_ERRORS_HPP
