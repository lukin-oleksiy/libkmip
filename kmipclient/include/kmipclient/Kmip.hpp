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

#ifndef KMIP_HPP
#define KMIP_HPP
#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"

#include <memory>

namespace kmipclient {
  /**
   * @brief Convenience wrapper that owns transport and client instances.
   *
   * This class builds and connects @ref NetClientOpenSSL and then exposes
   * the initialized @ref KmipClient instance.
   */
  class Kmip {
  public:
    /**
     * @brief Creates and connects an OpenSSL-based KMIP client stack.
     * @param host KMIP server hostname or IP address.
     * @param port KMIP server port.
     * @param clientCertificateFn Path to client X.509 certificate in PEM.
     * @param clientKeyFn Path to client private key in PEM.
     * @param serverCaCertFn Path to trusted server CA/certificate in PEM.
     * @param timeout_ms Connect/read/write timeout in milliseconds.
     * @param logger Optional KMIP protocol logger.
     * @throws kmipcore::KmipException when network/TLS initialization fails.
     */
    Kmip(
        const char *host,
        const char *port,
        const char *clientCertificateFn,
        const char *clientKeyFn,
        const char *serverCaCertFn,
        int timeout_ms,
        std::shared_ptr<kmipcore::Logger> logger = {}
    )
      : m_net_client(
            host,
            port,
            clientCertificateFn,
            clientKeyFn,
            serverCaCertFn,
            timeout_ms
        ),
        m_client(m_net_client, std::move(logger)) {
      m_net_client.connect();
    };

    /**
     * @brief Returns the initialized high-level KMIP client.
     * @return Mutable reference to the owned @ref KmipClient.
     */
    KmipClient &client() { return m_client; };

  private:
    /** @brief OpenSSL BIO-based network transport. */
    NetClientOpenSSL m_net_client;
    /** @brief High-level KMIP protocol client bound to @ref m_net_client. */
    KmipClient m_client;
  };
}  // namespace kmipclient
#endif  // KMIP_HPP
