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

#include "kmipclient/NetClientOpenSSL.hpp"

#include "kmipclient/KmipIOException.hpp"
#include "kmipcore/kmip_basics.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <sys/socket.h>
#include <sys/time.h>

namespace kmipclient {

  // Replaces get_openssl_error using Queue
  static std::string getOpenSslError() {
    std::ostringstream oss;
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
      char buf[256];
      ERR_error_string_n(err, buf, sizeof(buf));
      oss << buf << "; ";
    }
    std::string errStr = oss.str();
    if (errStr.empty()) {
      return "Unknown OpenSSL error";
    }
    return errStr;
  }

  static std::string timeoutMessage(const char *op, int timeout_ms) {
    std::ostringstream oss;
    oss << "KMIP " << op << " timed out after " << timeout_ms << "ms";
    return oss.str();
  }

  // Apply SO_RCVTIMEO / SO_SNDTIMEO on the underlying socket so that every
  // BIO_read / BIO_write call times out after timeout_ms milliseconds.
  // Must be called after BIO_do_connect() succeeds.
  static void apply_socket_io_timeout(BIO *bio, int timeout_ms) {
    if (timeout_ms <= 0) {
      return;
    }

    int fd = -1;
    if (BIO_get_fd(bio, &fd) < 0 || fd < 0) {
      // Unable to obtain socket fd – skip silently (non-fatal).
      return;
    }

    struct timeval tv {};
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
      throw KmipIOException(
          -1,
          "Failed to set SO_RCVTIMEO (" + std::to_string(timeout_ms) +
              "ms): " + strerror(errno)
      );
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
      throw KmipIOException(
          -1,
          "Failed to set SO_SNDTIMEO (" + std::to_string(timeout_ms) +
              "ms): " + strerror(errno)
      );
    }
  }

  // Returns true when errno indicates that a socket operation was interrupted
  // by the kernel because the configured SO_RCVTIMEO / SO_SNDTIMEO expired.
  static bool is_timeout_errno() {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT;
  }

  bool NetClientOpenSSL::checkConnected() {
    if (is_connected()) {
      return true;
    }
    return connect();
  }

  NetClientOpenSSL::NetClientOpenSSL(
      const std::string &host,
      const std::string &port,
      const std::string &clientCertificateFn,
      const std::string &clientKeyFn,
      const std::string &serverCaCertFn,
      int timeout_ms
  )
    : NetClient(
          host,
          port,
          clientCertificateFn,
          clientKeyFn,
          serverCaCertFn,
          timeout_ms
      ) {}

  NetClientOpenSSL::~NetClientOpenSSL() {
    // Avoid calling virtual methods from destructor.
    if (bio_) {
      bio_.reset();
    }
    if (ctx_) {
      ctx_.reset();
    }
    m_isConnected = false;
  }

  bool NetClientOpenSSL::connect() {
    // RAII for SSL_CTX
    ctx_.reset(SSL_CTX_new(TLS_method()));
    if (!ctx_) {
      throw KmipIOException(
          -1, "SSL_CTX_new failed: " + getOpenSslError()
      );
    }

    if (SSL_CTX_use_certificate_file(
            ctx_.get(), m_clientCertificateFn.c_str(), SSL_FILETYPE_PEM
        ) != 1) {
      throw KmipIOException(
          -1,
          "Loading client certificate failed: " + m_clientCertificateFn + " (" +
              getOpenSslError() + ")"
      );
    }

    if (SSL_CTX_use_PrivateKey_file(
            ctx_.get(), m_clientKeyFn.c_str(), SSL_FILETYPE_PEM
        ) != 1) {
      throw KmipIOException(
          -1,
          "Loading client key failed: " + m_clientKeyFn + " (" +
              getOpenSslError() + ")"
      );
    }

    if (SSL_CTX_load_verify_locations(
            ctx_.get(), m_serverCaCertificateFn.c_str(), nullptr
        ) != 1) {
      throw KmipIOException(
          -1,
          "Loading server CA certificate failed: " + m_serverCaCertificateFn +
              " (" + getOpenSslError() + ")"
      );
    }

    // RAII for BIO
    bio_.reset(BIO_new_ssl_connect(ctx_.get()));
    if (!bio_) {
      throw KmipIOException(
          -1, "BIO_new_ssl_connect failed: " + getOpenSslError()
      );
    }

    SSL *ssl = nullptr;
    BIO_get_ssl(bio_.get(), &ssl);
    if (!ssl) {
      throw KmipIOException(
          -1, "BIO_get_ssl failed: " + getOpenSslError()
      );
    }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio_.get(), m_host.c_str());
    BIO_set_conn_port(bio_.get(), m_port.c_str());

    // Using generic blocking BIO connect timeout if supported or rely on system
    // socket timeout BIO_set_ssl_renegotiate_timeout(bio_, m_timeout_ms); //
    // This function is non-standard or deprecated from initial code analysis.

    if (BIO_do_connect(bio_.get()) != 1) {
      throw KmipIOException(
          -1, "BIO_do_connect failed: " + getOpenSslError()
      );
    }

    // Apply per-operation I/O timeouts on the now-connected socket so that
    // every subsequent BIO_read / BIO_write times out after m_timeout_ms ms.
    apply_socket_io_timeout(bio_.get(), m_timeout_ms);

    m_isConnected = true;
    return true;
  }

  void NetClientOpenSSL::close() {
    if (bio_) {
      // BIO_free_all is called by unique_ptr reset
      bio_.reset();
    }
    if (ctx_) {
      ctx_.reset();
    }
    m_isConnected = false;
  }

  int NetClientOpenSSL::send(const void *data, int dlen) {
    if (!checkConnected()) {
      return -1;
    }
    const int ret = BIO_write(bio_.get(), data, dlen);
    if (ret <= 0 && is_timeout_errno()) {
      throw KmipIOException(
          -1, timeoutMessage("send", m_timeout_ms)
      );
    }
    return ret;
  }

  int NetClientOpenSSL::recv(void *data, int dlen) {
    if (!checkConnected()) {
      return -1;
    }
    const int ret = BIO_read(bio_.get(), data, dlen);
    if (ret <= 0 && is_timeout_errno()) {
      throw KmipIOException(
          -1, timeoutMessage("receive", m_timeout_ms)
      );
    }
    return ret;
  }

}  // namespace kmipclient
