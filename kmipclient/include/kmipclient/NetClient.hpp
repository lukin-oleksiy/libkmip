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

#ifndef KMIP_NET_CLIENT_HPP
#define KMIP_NET_CLIENT_HPP

#include <string>

namespace kmipclient {
  /**
   * @brief Abstract transport interface used by @ref KmipClient.
   *
   * Implementations provide connection lifecycle and raw byte send/receive
   * primitives over a secure channel.
   */
  class NetClient {
  public:
    /**
     * @brief Stores transport configuration.
     * @param host KMIP server host.
     * @param port KMIP server port.
     * @param clientCertificateFn Path to client X.509 certificate in PEM.
     * @param clientKeyFn Path to matching client private key in PEM.
     * @param serverCaCertFn Path to trusted server CA/certificate in PEM.
     * @param timeout_ms Connect/read/write timeout in milliseconds.
     */
    NetClient(
        const std::string &host,
        const std::string &port,
        const std::string &clientCertificateFn,
        const std::string &clientKeyFn,
        const std::string &serverCaCertFn,
        int timeout_ms
    ) noexcept
      : m_host(host),
        m_port(port),
        m_clientCertificateFn(clientCertificateFn),
        m_clientKeyFn(clientKeyFn),
        m_serverCaCertificateFn(serverCaCertFn),
        m_timeout_ms(timeout_ms) {};

    /** @brief Virtual destructor for interface-safe cleanup. */
    virtual ~NetClient() = default;
    // no copy, no move
    NetClient(const NetClient &) = delete;
    virtual NetClient &operator=(const NetClient &) = delete;
    NetClient(NetClient &&) = delete;
    virtual NetClient &operator=(NetClient &&) = delete;
    /**
     * @brief Establishes network/TLS connection to the KMIP server.
     * @return true on successful connection establishment, false otherwise.
     */

    virtual bool connect() = 0;
    /** @brief Closes the connection and releases underlying resources. */
    virtual void close() = 0;

    /**
     * @brief Checks whether a connection is currently established.
     * @return true when connected, false otherwise.
     */
    [[nodiscard]] bool is_connected() const { return m_isConnected; }
    /**
     * @brief Sends bytes over the established connection.
     * @param data Source buffer.
     * @param dlen Number of bytes to send.
     * @return Number of bytes sent, or -1 on failure.
     */
    virtual int send(const void *data, int dlen) = 0;

    /**
     * @brief Receives bytes from the established connection.
     * @param data Destination buffer.
     * @param dlen Number of bytes requested.
     * @return Number of bytes received, or -1 on failure.
     */
    virtual int recv(void *data, int dlen) = 0;

  protected:
    std::string m_host;
    std::string m_port;
    std::string m_clientCertificateFn;
    std::string m_clientKeyFn;
    std::string m_serverCaCertificateFn;
    int m_timeout_ms;
    bool m_isConnected = false;
  };
}  // namespace kmipclient
#endif  // KMIP_NET_CLIENT_HPP
