#include "kmipcore/kmip_requests.hpp"

namespace kmipcore {

  namespace detail {
    std::shared_ptr<Element> make_text_attribute(
        const std::string &attribute_name, const std::string &value
    ) {
      auto attribute =
          Element::createStructure(static_cast<Tag>(KMIP_TAG_ATTRIBUTE));
      attribute->asStructure()->add(
          Element::createTextString(
              static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), attribute_name
          )
      );
      auto attribute_value = Element::createTextString(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_VALUE), value
      );
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element>
        make_enum_attribute(const std::string &attribute_name, int32_t value) {
      auto attribute =
          Element::createStructure(static_cast<Tag>(KMIP_TAG_ATTRIBUTE));
      attribute->asStructure()->add(
          Element::createTextString(
              static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), attribute_name
          )
      );
      auto attribute_value = Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_VALUE), value
      );
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element> make_integer_attribute(
        const std::string &attribute_name, int32_t value
    ) {
      auto attribute =
          Element::createStructure(static_cast<Tag>(KMIP_TAG_ATTRIBUTE));
      attribute->asStructure()->add(
          Element::createTextString(
              static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), attribute_name
          )
      );
      auto attribute_value = Element::createInteger(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_VALUE), value
      );
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element> make_name_attribute(const std::string &value) {
      auto attribute_value =
          Element::createStructure(static_cast<Tag>(KMIP_TAG_ATTRIBUTE_VALUE));
      attribute_value->asStructure()->add(
          Element::createTextString(
              static_cast<Tag>(KMIP_TAG_NAME_VALUE), value
          )
      );
      attribute_value->asStructure()->add(
          Element::createEnumeration(
              static_cast<Tag>(KMIP_TAG_NAME_TYPE),
              KMIP_NAME_UNINTERPRETED_TEXT_STRING
          )
      );
      auto attribute =
          Element::createStructure(static_cast<Tag>(KMIP_TAG_ATTRIBUTE));
      attribute->asStructure()->add(
          Element::createTextString(
              static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), "Name"
          )
      );
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element> make_template_attribute(
        const std::vector<std::shared_ptr<Element>> &attributes
    ) {
      auto template_attribute = Element::createStructure(
          static_cast<Tag>(KMIP_TAG_TEMPLATE_ATTRIBUTE)
      );
      for (const auto &attribute : attributes) {
        template_attribute->asStructure()->add(attribute);
      }
      return template_attribute;
    }
    std::shared_ptr<Element>
        make_key_value(const std::vector<unsigned char> &bytes) {
      auto key_value =
          Element::createStructure(static_cast<Tag>(KMIP_TAG_KEY_VALUE));
      key_value->asStructure()->add(
          Element::createByteString(
              static_cast<Tag>(KMIP_TAG_KEY_MATERIAL),
              std::vector<uint8_t>(bytes.begin(), bytes.end())
          )
      );
      return key_value;
    }
    std::shared_ptr<Element> make_key_block(
        int32_t key_format_type,
        const std::vector<unsigned char> &bytes,
        std::optional<int32_t> algorithm,
        std::optional<int32_t> cryptographic_length
    ) {
      auto key_block =
          Element::createStructure(static_cast<Tag>(KMIP_TAG_KEY_BLOCK));
      key_block->asStructure()->add(
          Element::createEnumeration(
              static_cast<Tag>(KMIP_TAG_KEY_FORMAT_TYPE), key_format_type
          )
      );
      key_block->asStructure()->add(make_key_value(bytes));
      if (algorithm) {
        key_block->asStructure()->add(
            Element::createEnumeration(
                static_cast<Tag>(KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM), *algorithm
            )
        );
      }
      if (cryptographic_length) {
        key_block->asStructure()->add(
            Element::createInteger(
                static_cast<Tag>(KMIP_TAG_CRYPTOGRAPHIC_LENGTH),
                *cryptographic_length
            )
        );
      }
      return key_block;
    }
    std::shared_ptr<Element>
        make_symmetric_key(const std::vector<unsigned char> &key_value) {
      auto symmetric_key =
          Element::createStructure(static_cast<Tag>(KMIP_TAG_SYMMETRIC_KEY));
      symmetric_key->asStructure()->add(make_key_block(
          KMIP_KEYFORMAT_RAW,
          key_value,
          KMIP_CRYPTOALG_AES,
          static_cast<int32_t>(key_value.size() * 8)
      ));
      return symmetric_key;
    }
    std::shared_ptr<Element>
        make_secret_data(const secret_t &secret, int32_t secret_type) {
      auto secret_data =
          Element::createStructure(static_cast<Tag>(KMIP_TAG_SECRET_DATA));
      secret_data->asStructure()->add(
          Element::createEnumeration(
              static_cast<Tag>(KMIP_TAG_SECRET_DATA_TYPE), secret_type
          )
      );
      secret_data->asStructure()->add(make_key_block(
          KMIP_KEYFORMAT_OPAQUE, secret, std::nullopt, std::nullopt
      ));
      return secret_data;
    }
  }  // namespace detail

  // ---------------------------------------------------------------------------
  // CreateSymmetricKeyRequest
  // ---------------------------------------------------------------------------
  CreateSymmetricKeyRequest::CreateSymmetricKeyRequest(
      const std::string &name, const std::string &group
  ) {
    setOperation(KMIP_OP_CREATE);

    std::vector<std::shared_ptr<Element>> attributes;
    attributes.push_back(
        detail::make_enum_attribute(
            "Cryptographic Algorithm", KMIP_CRYPTOALG_AES
        )
    );
    attributes.push_back(
        detail::make_integer_attribute("Cryptographic Length", 256)
    );
    attributes.push_back(
        detail::make_integer_attribute(
            "Cryptographic Usage Mask",
            KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT
        )
    );
    attributes.push_back(detail::make_name_attribute(name));
    if (!group.empty()) {
      attributes.push_back(detail::make_text_attribute("Object Group", group));
    }

    auto payload =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_REQUEST_PAYLOAD));
    payload->asStructure()->add(
        Element::createEnumeration(
            static_cast<Tag>(KMIP_TAG_OBJECT_TYPE), KMIP_OBJTYPE_SYMMETRIC_KEY
        )
    );
    payload->asStructure()->add(detail::make_template_attribute(attributes));
    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // RegisterSymmetricKeyRequest
  // ---------------------------------------------------------------------------
  RegisterSymmetricKeyRequest::RegisterSymmetricKeyRequest(
      const std::string &name,
      const std::string &group,
      const std::vector<unsigned char> &key_value
  ) {
    setOperation(KMIP_OP_REGISTER);

    std::vector<std::shared_ptr<Element>> attributes;
    attributes.push_back(
        detail::make_enum_attribute(
            "Cryptographic Algorithm", KMIP_CRYPTOALG_AES
        )
    );
    attributes.push_back(
        detail::make_integer_attribute(
            "Cryptographic Length", static_cast<int32_t>(key_value.size() * 8)
        )
    );
    attributes.push_back(
        detail::make_integer_attribute(
            "Cryptographic Usage Mask",
            KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT
        )
    );
    attributes.push_back(detail::make_name_attribute(name));
    if (!group.empty()) {
      attributes.push_back(detail::make_text_attribute("Object Group", group));
    }

    auto payload =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_REQUEST_PAYLOAD));
    payload->asStructure()->add(
        Element::createEnumeration(
            static_cast<Tag>(KMIP_TAG_OBJECT_TYPE), KMIP_OBJTYPE_SYMMETRIC_KEY
        )
    );
    payload->asStructure()->add(detail::make_template_attribute(attributes));
    payload->asStructure()->add(detail::make_symmetric_key(key_value));
    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // RegisterSecretRequest
  // ---------------------------------------------------------------------------
  RegisterSecretRequest::RegisterSecretRequest(
      const std::string &name,
      const std::string &group,
      const secret_t &secret,
      int32_t secret_type
  ) {
    setOperation(KMIP_OP_REGISTER);

    std::vector<std::shared_ptr<Element>> attributes;
    attributes.push_back(
        detail::make_integer_attribute(
            "Cryptographic Usage Mask",
            KMIP_CRYPTOMASK_DERIVE_KEY | KMIP_CRYPTOMASK_EXPORT
        )
    );
    attributes.push_back(detail::make_name_attribute(name));
    if (!group.empty()) {
      attributes.push_back(detail::make_text_attribute("Object Group", group));
    }

    auto payload =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_REQUEST_PAYLOAD));
    payload->asStructure()->add(
        Element::createEnumeration(
            static_cast<Tag>(KMIP_TAG_OBJECT_TYPE), KMIP_OBJTYPE_SECRET_DATA
        )
    );
    payload->asStructure()->add(detail::make_template_attribute(attributes));
    payload->asStructure()->add(detail::make_secret_data(secret, secret_type));
    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // LocateRequest
  // ---------------------------------------------------------------------------
  LocateRequest::LocateRequest(
      bool locate_by_group,
      const std::string &name,
      int32_t object_type,
      size_t max_items,
      size_t offset
  ) {
    setOperation(KMIP_OP_LOCATE);

    auto payload =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_REQUEST_PAYLOAD));
    if (max_items > 0) {
      payload->asStructure()->add(
          Element::createInteger(
              static_cast<Tag>(KMIP_TAG_MAXIMUM_ITEMS),
              static_cast<int32_t>(max_items)
          )
      );
    }
    if (offset > 0) {
      payload->asStructure()->add(
          Element::createInteger(
              static_cast<Tag>(KMIP_TAG_OFFSET_ITEMS),
              static_cast<int32_t>(offset)
          )
      );
    }

    payload->asStructure()->add(
        detail::make_enum_attribute("Object Type", object_type)
    );
    if (!name.empty()) {
      if (locate_by_group) {
        payload->asStructure()->add(
            detail::make_text_attribute("Object Group", name)
        );
      } else {
        payload->asStructure()->add(detail::make_name_attribute(name));
      }
    }
    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // RevokeRequest
  // ---------------------------------------------------------------------------
  RevokeRequest::RevokeRequest(
      const std::string &unique_id,
      int32_t reason,
      const std::string &message,
      time_t occurrence_time
  ) {
    setOperation(KMIP_OP_REVOKE);

    auto payload =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_REQUEST_PAYLOAD));
    payload->asStructure()->add(
        Element::createTextString(
            static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), unique_id
        )
    );

    auto revocation_reason =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_REVOCATION_REASON));
    revocation_reason->asStructure()->add(
        Element::createEnumeration(
            static_cast<Tag>(KMIP_TAG_REVOCATION_REASON_CODE), reason
        )
    );
    if (!message.empty()) {
      revocation_reason->asStructure()->add(
          Element::createTextString(
              static_cast<Tag>(KMIP_TAG_REVOKATION_MESSAGE), message
          )
      );
    }
    payload->asStructure()->add(revocation_reason);

    if (occurrence_time > 0) {
      payload->asStructure()->add(
          Element::createDateTime(
              static_cast<Tag>(KMIP_TAG_COMPROMISE_OCCURRANCE_DATE),
              static_cast<int64_t>(occurrence_time)
          )
      );
    }
    setRequestPayload(payload);
  }


}  // namespace kmipcore
