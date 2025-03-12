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

#include "kmipclient/KmipClient.hpp"

#include "IOUtils.hpp"
#include "kmipcore/attributes_parser.hpp"
#include "kmipcore/key_parser.hpp"
#include "kmipcore/kmip_requests.hpp"
#include "kmipcore/response_parser.hpp"

namespace kmipclient {

  KmipClient::KmipClient(
      NetClient &net_client, std::shared_ptr<kmipcore::Logger> logger
  )
    : net_client(net_client),
      io(std::make_unique<IOUtils>(net_client, std::move(logger))) {};


  KmipClient::~KmipClient() {
    net_client.close();
  };

  id_t KmipClient::op_register_key(
      const name_t &name, const name_t &group, const Key &k
  ) const {
    kmipcore::RequestMessage request;
    const auto batch_item_id = request.add_batch_item(
        kmipcore::RegisterSymmetricKeyRequest(name, group, k.value())
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    return rf
        .getResponseByBatchItemId<kmipcore::RegisterResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  id_t KmipClient::op_register_secret(
      const name_t &name,
      const name_t &group,
      const std::string_view secret,
      enum secret_data_type secret_type
  ) const {
    return op_register_secret(
        name,
        group,
        secret_t(secret.begin(), secret.end()),
        secret_type
    );
  }

  id_t KmipClient::op_register_secret(
      const name_t &name,
      const name_t &group,
      const secret_t &secret,
      enum secret_data_type secret_type
  ) const {
    kmipcore::RequestMessage request;
    const auto batch_item_id = request.add_batch_item(
        kmipcore::RegisterSecretRequest(name, group, secret, secret_type)
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    return rf
        .getResponseByBatchItemId<kmipcore::RegisterResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  id_t KmipClient::op_create_aes_key(
      const name_t &name, const name_t &group
  ) const {
    kmipcore::RequestMessage request;
    const auto batch_item_id = request.add_batch_item(
        kmipcore::CreateSymmetricKeyRequest(name, group)
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    return rf
        .getResponseByBatchItemId<kmipcore::CreateResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  Key KmipClient::op_get_key(const id_t &id, bool all_attributes) const {
    kmipcore::RequestMessage request;
    const auto get_item_id = request.add_batch_item(kmipcore::GetRequest(id));

    std::vector<std::string> requested_attrs;
    if (!all_attributes) {
      requested_attrs = {KMIP_ATTR_NAME_STATE, KMIP_ATTR_NAME_NAME};
    }

    const auto attributes_item_id = request.add_batch_item(
        kmipcore::GetAttributesRequest(id, requested_attrs)
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    auto get_response =
        rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
            get_item_id
        );
    auto key = kmipcore::KeyParser::parseGetKeyResponse(get_response);

    auto attrs_response =
        rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
            attributes_item_id
        );
    attributes_t attrs =
        kmipcore::AttributesParser::parse(attrs_response.getAttributes());

    if (all_attributes) {
      for (const auto &item : attrs) {
        key.set_attribute(item.first, item.second);
      }
    } else {
      key.set_attribute(KMIP_ATTR_NAME_STATE, attrs[KMIP_ATTR_NAME_STATE]);
      key.set_attribute(KMIP_ATTR_NAME_NAME, attrs[KMIP_ATTR_NAME_NAME]);
    }

    return key;
  }

  Secret KmipClient::op_get_secret(const id_t &id, bool all_attributes) const {
    kmipcore::RequestMessage request;
    const auto get_item_id = request.add_batch_item(kmipcore::GetRequest(id));

    std::vector<std::string> requested_attrs;
    if (!all_attributes) {
      requested_attrs = {KMIP_ATTR_NAME_STATE, KMIP_ATTR_NAME_NAME};
    }

    const auto attributes_item_id = request.add_batch_item(
        kmipcore::GetAttributesRequest(id, requested_attrs)
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    auto get_response =
        rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
            get_item_id
        );
    Secret secret;
    try {
      secret = kmipcore::KeyParser::parseGetSecretResponse(get_response);
    } catch (const kmipcore::KmipException &e) {
      if (std::string(e.what()) == "Secret data expected in Get response.") {
        throw kmipcore::KmipException(
            "Message: Could not locate object: " + id +
            "\nOperation: Get; Result status: Operation Failed; "
            "Result reason: 1"
        );
      }
      throw;
    }

    auto attrs_response =
        rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
            attributes_item_id
        );
    attributes_t attrs =
        kmipcore::AttributesParser::parse(attrs_response.getAttributes());

    if (all_attributes) {
      for (const auto &item : attrs) {
        secret.set_attribute(item.first, item.second);
      }
    } else {
      secret.set_attribute(KMIP_ATTR_NAME_STATE, attrs[KMIP_ATTR_NAME_STATE]);
      secret.set_attribute(KMIP_ATTR_NAME_NAME, attrs[KMIP_ATTR_NAME_NAME]);
    }

    return secret;
  }

  id_t KmipClient::op_activate(const id_t &id) const {
    kmipcore::RequestMessage request;
    const auto batch_item_id =
        request.add_batch_item(kmipcore::ActivateRequest(id));

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    return rf
        .getResponseByBatchItemId<kmipcore::ActivateResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  names_t KmipClient::op_get_attribute_list(const id_t &id) const {
    kmipcore::RequestMessage request;
    const auto batch_item_id =
        request.add_batch_item(kmipcore::GetAttributeListRequest(id));

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    auto response = rf.getResponseByBatchItemId<
        kmipcore::GetAttributeListResponseBatchItem>(batch_item_id);
    return names_t{
        response.getAttributeNames().begin(), response.getAttributeNames().end()
    };
  }

  attributes_t KmipClient::op_get_attributes(
      const id_t &id, const std::vector<name_t> &attr_names
  ) const {
    kmipcore::RequestMessage request;
    const auto batch_item_id =
        request.add_batch_item(kmipcore::GetAttributesRequest(id, attr_names));

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    auto response =
        rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
            batch_item_id
        );
    return kmipcore::AttributesParser::parse(response.getAttributes());
  }

  ids_t KmipClient::op_locate_by_name(
      const name_t &name, enum object_type o_type
  ) const {
    kmipcore::RequestMessage request;
    const auto batch_item_id = request.add_batch_item(
        kmipcore::LocateRequest(false, name, o_type, MAX_ITEMS_IN_BATCH, 0)
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    auto response =
        rf.getResponseByBatchItemId<kmipcore::LocateResponseBatchItem>(
            batch_item_id
        );
    return ids_t{
        response.getUniqueIdentifiers().begin(),
        response.getUniqueIdentifiers().end()
    };
  }

  ids_t KmipClient::op_locate_by_group(
      const name_t &group, enum object_type o_type, size_t max_ids
  ) const {
    ids_t result;
    size_t received = 0;
    size_t offset = 0;

    do {
      kmipcore::RequestMessage request;
      const auto batch_item_id = request.add_batch_item(
          kmipcore::LocateRequest(
              true, group, o_type, MAX_ITEMS_IN_BATCH, offset
          )
      );

      std::vector<uint8_t> response_bytes;
      io->do_exchange(
          request.serialize(), response_bytes, request.getMaxResponseSize()
      );

      kmipcore::ResponseParser rf(response_bytes);
      auto response =
          rf.getResponseByBatchItemId<kmipcore::LocateResponseBatchItem>(
              batch_item_id
          );
      auto exp = ids_t(
          response.getUniqueIdentifiers().begin(),
          response.getUniqueIdentifiers().end()
      );

      if (ids_t got = exp; !got.empty()) {
        received = got.size();
        offset += got.size();
        result.insert(result.end(), got.begin(), got.end());
      } else {
        break;
      }
    } while (received == MAX_ITEMS_IN_BATCH && result.size() < max_ids);

    return result;
  }

  ids_t KmipClient::op_all(enum object_type o_type, size_t max_ids) const {
    return op_locate_by_group("", o_type, max_ids);
  }

  id_t KmipClient::op_revoke(
      const id_t &id,
      enum revocation_reason_type reason,
      const name_t &message,
      time_t occurrence_time
  ) const {
    kmipcore::RequestMessage request;
    const auto batch_item_id = request.add_batch_item(
        kmipcore::RevokeRequest(id, reason, message, occurrence_time)
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    return rf
        .getResponseByBatchItemId<kmipcore::RevokeResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  id_t KmipClient::op_destroy(const id_t &id) const {
    kmipcore::RequestMessage request;
    const auto batch_item_id =
        request.add_batch_item(kmipcore::DestroyRequest(id));

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes);
    return rf
        .getResponseByBatchItemId<kmipcore::DestroyResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

}  // namespace kmipclient
