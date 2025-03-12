#pragma once

#include "kmipcore/kmip_protocol.hpp"

namespace kmipcore {

  namespace detail {
    /** @brief Validates response operation code against expected value. */
    inline void expect_operation(
        const ResponseBatchItem &item,
        int32_t expectedOperation,
        const char *className
    ) {
      if (item.getOperation() != expectedOperation) {
        throw KmipException(
            std::string(className) +
            ": unexpected operation in response batch item"
        );
      }
    }

    /** @brief Returns response payload or throws when it is missing. */
    inline std::shared_ptr<Element> require_response_payload(
        const ResponseBatchItem &item, const char *className
    ) {
      auto payload = item.getResponsePayload();
      if (!payload) {
        throw KmipException(
            std::string(className) + ": missing response payload"
        );
      }
      return payload;
    }
  }  // namespace detail

  // ---------------------------------------------------------------------------
  // CRTP Base class to reduce boilerplate for fromElement and constructors.
  // ---------------------------------------------------------------------------
  template<typename Derived>
  class BaseResponseBatchItem : public ResponseBatchItem {
  public:
    using ResponseBatchItem::ResponseBatchItem;

    /** @brief Constructs typed wrapper from plain response batch item. */
    explicit BaseResponseBatchItem(const ResponseBatchItem &other)
      : ResponseBatchItem(other) {}

    /** @brief Decodes typed wrapper directly from TTLV element form. */
    static Derived fromElement(std::shared_ptr<Element> element) {
      return Derived::fromBatchItem(
          ResponseBatchItem::fromElement(std::move(element))
      );
    }
  };

  // ---------------------------------------------------------------------------
  // Common base template for simple response batch items that only carry a
  // unique-identifier extracted from the response payload.
  // OpCode is the expected KMIP operation enum value (e.g. KMIP_OP_CREATE).
  // ---------------------------------------------------------------------------
  template<int32_t OpCode>
  class SimpleIdResponseBatchItem
    : public BaseResponseBatchItem<SimpleIdResponseBatchItem<OpCode>> {
  public:
    using Base = BaseResponseBatchItem<SimpleIdResponseBatchItem<OpCode>>;
    using Base::Base;  // Inherit constructors

    /** @brief Converts generic response item into typed simple-id response. */
    static SimpleIdResponseBatchItem
        fromBatchItem(const ResponseBatchItem &item) {
      detail::expect_operation(item, OpCode, "SimpleIdResponseBatchItem");

      SimpleIdResponseBatchItem result(item);
      auto payload =
          detail::require_response_payload(item, "SimpleIdResponseBatchItem");

      auto uid =
          payload->getChild(static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER));
      if (!uid) {
        throw KmipException(
            "SimpleIdResponseBatchItem: missing unique identifier in response "
            "payload"
        );
      }
      result.uniqueIdentifier_ = uid->toString();
      return result;
    }

    /** @brief Returns response unique identifier field. */
    [[nodiscard]] const std::string &getUniqueIdentifier() const {
      return uniqueIdentifier_;
    }

  private:
    std::string uniqueIdentifier_;
  };

  /** @brief Typed response alias for KMIP Create operation. */
  using CreateResponseBatchItem = SimpleIdResponseBatchItem<KMIP_OP_CREATE>;
  /** @brief Typed response alias for KMIP Register operation. */
  using RegisterResponseBatchItem = SimpleIdResponseBatchItem<KMIP_OP_REGISTER>;
  /** @brief Typed response alias for KMIP Activate operation. */
  using ActivateResponseBatchItem = SimpleIdResponseBatchItem<KMIP_OP_ACTIVATE>;
  /** @brief Typed response alias for KMIP Revoke operation. */
  using RevokeResponseBatchItem = SimpleIdResponseBatchItem<KMIP_OP_REVOKE>;
  /** @brief Typed response alias for KMIP Destroy operation. */
  using DestroyResponseBatchItem = SimpleIdResponseBatchItem<KMIP_OP_DESTROY>;

  // ---------------------------------------------------------------------------
  // Response types with additional fields beyond unique-identifier.
  // ---------------------------------------------------------------------------

  /** @brief Typed response for KMIP Get operation. */
  class GetResponseBatchItem
    : public BaseResponseBatchItem<GetResponseBatchItem> {
  public:
    using BaseResponseBatchItem::BaseResponseBatchItem;

    /** @brief Converts generic response item into Get response view. */
    static GetResponseBatchItem fromBatchItem(const ResponseBatchItem &item);

    /** @brief Returns unique identifier from response payload. */
    [[nodiscard]] const std::string &getUniqueIdentifier() const {
      return uniqueIdentifier_;
    }
    /** @brief Returns KMIP object_type value from response payload. */
    [[nodiscard]] int32_t getObjectType() const { return objectType_; }
    /** @brief Returns element containing the returned KMIP object content. */
    [[nodiscard]] std::shared_ptr<Element> getObjectElement() const {
      return objectElement_;
    }

  private:
    std::string uniqueIdentifier_;
    int32_t objectType_ = 0;
    std::shared_ptr<Element> objectElement_;
  };

  /** @brief Typed response for KMIP Get Attributes operation. */
  class GetAttributesResponseBatchItem
    : public BaseResponseBatchItem<GetAttributesResponseBatchItem> {
  public:
    using BaseResponseBatchItem::BaseResponseBatchItem;

    /** @brief Converts generic response item into Get Attributes response. */
    static GetAttributesResponseBatchItem
        fromBatchItem(const ResponseBatchItem &item);

    /** @brief Returns raw attribute elements carried by the payload. */
    [[nodiscard]] const std::vector<std::shared_ptr<Element>> &getAttributes() const {
      return attributes_;
    }

  private:
    std::vector<std::shared_ptr<Element>> attributes_;
  };

  /** @brief Typed response for KMIP Get Attribute List operation. */
  class GetAttributeListResponseBatchItem
    : public BaseResponseBatchItem<GetAttributeListResponseBatchItem> {
  public:
    using BaseResponseBatchItem::BaseResponseBatchItem;

    /** @brief Converts generic response item into Get Attribute List response. */
    static GetAttributeListResponseBatchItem
        fromBatchItem(const ResponseBatchItem &item);

    /** @brief Returns attribute names present in the target object. */
    [[nodiscard]] const std::vector<std::string> &getAttributeNames() const {
      return attributeNames_;
    }

  private:
    std::vector<std::string> attributeNames_;
  };

  /** @brief Typed response for KMIP Locate operation. */
  class LocateResponseBatchItem
    : public BaseResponseBatchItem<LocateResponseBatchItem> {
  public:
    using BaseResponseBatchItem::BaseResponseBatchItem;

    /** @brief Converts generic response item into Locate response view. */
    static LocateResponseBatchItem fromBatchItem(const ResponseBatchItem &item);

    /** @brief Returns parsed locate payload metadata and identifiers. */
    [[nodiscard]] const LocateResponsePayload &getLocatePayload() const {
      return locatePayload_;
    }
    /** @brief Returns located unique identifiers from payload. */
    [[nodiscard]] const std::vector<std::string> &getUniqueIdentifiers() const {
      return locatePayload_.getUniqueIdentifiers();
    }

  private:
    LocateResponsePayload locatePayload_;
  };


}  // namespace kmipcore
