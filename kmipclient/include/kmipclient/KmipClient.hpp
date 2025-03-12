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
#ifndef KMIP_CLIENT_HPP
#define KMIP_CLIENT_HPP

#include "kmipclient/Key.hpp"
#include "kmipclient/NetClient.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_logger.hpp"

#include <memory>

namespace kmipclient {

  /** Maximum number of KMIP locate response batches processed by search helpers. */
  constexpr size_t MAX_BATCHES_IN_SEARCH = 16;
  /** Maximum number of response items expected per single KMIP batch. */
  constexpr size_t MAX_ITEMS_IN_BATCH = 1024;

  class IOUtils;
  /**
   * @brief High-level KMIP client API for key and secret lifecycle operations.
   *
   * The instance uses an already configured and connected @ref NetClient
   * transport and provides typed wrappers around common KMIP operations.
   */
  class KmipClient {
  public:
    /**
     * @brief Creates a client bound to an existing transport.
     * @param net_client Pre-initialized network transport implementation.
     * @param logger Optional KMIP protocol logger. When set, serialized TTLV
     * request and response payloads are logged at DEBUG level.
     */
    explicit KmipClient(
        NetClient &net_client,
        std::shared_ptr<kmipcore::Logger> logger = {}
    );
    /** @brief Destroys the client and internal helpers. */
    ~KmipClient();
    // no copy, no move
    KmipClient(const KmipClient &) = delete;
    KmipClient &operator=(const KmipClient &) = delete;
    KmipClient(KmipClient &&) = delete;
    KmipClient &operator=(KmipClient &&) = delete;

    /**
     * @brief Executes KMIP Register for a key object.
     * @param name Value of the KMIP "Name" attribute.
     * @param group Value of the KMIP "Object Group" attribute.
     * @param k Key material and metadata to register.
     * @return Unique identifier assigned by the KMIP server.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] id_t op_register_key(
        const name_t &name, const name_t &group, const Key &k
    ) const;

    /**
     * @brief Executes KMIP Register for secret data provided as text bytes.
     * @param name Value of the KMIP "Name" attribute.
     * @param group Value of the KMIP "Object Group" attribute.
     * @param secret Secret payload to store.
     * @param secret_type KMIP Secret Data Type for the payload.
     * @return Unique identifier assigned by the KMIP server.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] id_t op_register_secret(
        const name_t &name,
        const name_t &group,
        std::string_view secret,
        enum secret_data_type secret_type
    ) const;

    /**
     * @brief Executes KMIP Register for binary secret data.
     * @param name Value of the KMIP "Name" attribute.
     * @param group Value of the KMIP "Object Group" attribute.
     * @param secret Binary secret payload to store.
     * @param secret_type KMIP Secret Data Type for the payload.
     * @return Unique identifier assigned by the KMIP server.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] id_t op_register_secret(
        const name_t &name,
        const name_t &group,
        const secret_t &secret,
        enum secret_data_type secret_type
    ) const;

    /**
     * @brief Executes KMIP Create to generate a server-side AES-256 key.
     * @param name Value of the KMIP "Name" attribute.
     * @param group Value of the KMIP "Object Group" attribute.
     * @return Unique identifier of the created key.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] id_t
        op_create_aes_key(const name_t &name, const name_t &group) const;

    /**
     * @brief Executes KMIP Get and decodes a key object.
     * @param id Unique identifier of the key object.
     * @param all_attributes When true, fetches all available attributes.
     * @return Decoded key object.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] Key op_get_key(const id_t &id, bool all_attributes = false) const;

    /**
     * @brief Executes KMIP Get and decodes a secret object.
     * @param id Unique identifier of the secret object.
     * @param all_attributes When true, fetches all available attributes.
     * @return Decoded secret object.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] Secret
        op_get_secret(const id_t &id, bool all_attributes = false) const;

    /**
     * @brief Executes KMIP Activate for a managed object.
     * @param id Unique identifier of the object to activate.
     * @return Identifier returned by the server (normally equals @p id).
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] id_t op_activate(const id_t &id) const;

    /**
     * @brief Executes KMIP Get Attribute List.
     * @param id Unique identifier of the target object.
     * @return List of attribute names available for the object.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] names_t op_get_attribute_list(const id_t &id) const;

    /**
     * @brief Executes KMIP Get Attributes for selected attribute names.
     * @param id Unique identifier of the target object.
     * @param attr_names Attribute names to fetch (for example "Name", "State").
     * @return Map of requested attributes present in the server response.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] attributes_t op_get_attributes(
        const id_t &id, const std::vector<name_t> &attr_names
    ) const;

    /**
     * @brief Executes KMIP Locate using an exact object name filter.
     * @param name Object name to match.
     * @param o_type KMIP object type to search.
     * @return Matching object identifiers; may contain multiple IDs.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] ids_t
        op_locate_by_name(const name_t &name, enum object_type o_type) const;

    /**
     * @brief Executes KMIP Locate using the object group filter.
     * @param group Group name to match.
     * @param o_type KMIP object type to search.
     * @param max_ids Upper bound on collected IDs across locate batches.
     * @return Matching object identifiers, up to @p max_ids entries.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] ids_t op_locate_by_group(
        const name_t &group,
        enum object_type o_type,
        size_t max_ids = MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH
    ) const;

    /**
     * @brief Executes KMIP Revoke for a managed object.
     * @param id Unique identifier of the object to revoke.
     * @param reason KMIP revocation reason code.
     * @param message Optional human-readable revocation message.
     * @param occurrence_time Incident time for reasons that require it; use 0
     * for regular deactivation flows.
     * @return Identifier returned by the server (normally equals @p id).
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] id_t op_revoke(
        const id_t &id,
        enum revocation_reason_type reason,
        const name_t &message,
        time_t occurrence_time
    ) const;
    /**
     * @brief Executes KMIP Destroy for a managed object.
     * @param id Unique identifier of the object to destroy.
     * @return Identifier returned by the server (normally equals @p id).
     * @throws kmipcore::KmipException on protocol or server-side failure.
     * @note Most KMIP servers require the object to be revoked first.
     */
    [[nodiscard]] id_t op_destroy(const id_t &id) const;

    /**
     * @brief Executes KMIP Locate without name/group filters.
     * @param o_type KMIP object type to fetch.
     * @param max_ids Upper bound on collected IDs across locate batches.
     * @return Identifiers of matching objects, up to @p max_ids entries.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] ids_t op_all(
        enum object_type o_type,
        size_t max_ids = MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH
    ) const;

  private:
    NetClient &net_client;
    std::unique_ptr<IOUtils> io;
  };

}  // namespace kmipclient
#endif  // KMIP_CLIENT_HPP
