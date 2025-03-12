#include "kmipcore/kmip_responses.hpp"

namespace kmipcore {

  namespace {

    std::shared_ptr<Element> get_object_element_for_type(
        const std::shared_ptr<Element> &payload, int32_t objectType
    ) {
      switch (objectType) {
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
          return payload->getChild(static_cast<Tag>(KMIP_TAG_SYMMETRIC_KEY));
        case KMIP_OBJTYPE_SECRET_DATA:
          return payload->getChild(static_cast<Tag>(KMIP_TAG_SECRET_DATA));
        case KMIP_OBJTYPE_PRIVATE_KEY:
          return payload->getChild(static_cast<Tag>(KMIP_TAG_PRIVATE_KEY));
        case KMIP_OBJTYPE_PUBLIC_KEY:
          return payload->getChild(static_cast<Tag>(KMIP_TAG_PUBLIC_KEY));
        default:
          return {};
      }
    }

  }  // namespace

  // --- GetResponseBatchItem ---

  GetResponseBatchItem
      GetResponseBatchItem::fromBatchItem(const ResponseBatchItem &item) {
    detail::expect_operation(item, KMIP_OP_GET, "GetResponseBatchItem");

    GetResponseBatchItem result(item);

    auto payload =
        detail::require_response_payload(item, "GetResponseBatchItem");

    auto uniqueIdentifier =
        payload->getChild(static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER));
    if (!uniqueIdentifier) {
      throw KmipException(
          "GetResponseBatchItem: missing unique identifier in response payload"
      );
    }
    result.uniqueIdentifier_ = uniqueIdentifier->toString();

    auto objectType = payload->getChild(static_cast<Tag>(KMIP_TAG_OBJECT_TYPE));
    if (!objectType) {
      throw KmipException(
          "GetResponseBatchItem: missing object type in response payload"
      );
    }

    result.objectType_ = objectType->toEnum();
    result.objectElement_ =
        get_object_element_for_type(payload, result.objectType_);
    if (!result.objectElement_) {
      throw KmipException(
          "GetResponseBatchItem: missing object payload for object type"
      );
    }

    return result;
  }

  // --- GetAttributesResponseBatchItem ---

  GetAttributesResponseBatchItem GetAttributesResponseBatchItem::fromBatchItem(
      const ResponseBatchItem &item
  ) {
    detail::expect_operation(
        item, KMIP_OP_GET_ATTRIBUTES, "GetAttributesResponseBatchItem"
    );

    GetAttributesResponseBatchItem result(item);
    auto payload = detail::require_response_payload(
        item, "GetAttributesResponseBatchItem"
    );
    result.attributes_ =
        payload->getChildren(static_cast<Tag>(KMIP_TAG_ATTRIBUTE));
    return result;
  }

  // --- GetAttributeListResponseBatchItem ---

  GetAttributeListResponseBatchItem
      GetAttributeListResponseBatchItem::fromBatchItem(
          const ResponseBatchItem &item
      ) {
    detail::expect_operation(
        item, KMIP_OP_GET_ATTRIBUTE_LIST, "GetAttributeListResponseBatchItem"
    );

    GetAttributeListResponseBatchItem result(item);
    auto payload = detail::require_response_payload(
        item, "GetAttributeListResponseBatchItem"
    );

    for (const auto &attributeName :
         payload->getChildren(static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME))) {
      result.attributeNames_.push_back(attributeName->toString());
    }

    return result;
  }

  // --- LocateResponseBatchItem ---

  LocateResponseBatchItem
      LocateResponseBatchItem::fromBatchItem(const ResponseBatchItem &item) {
    detail::expect_operation(item, KMIP_OP_LOCATE, "LocateResponseBatchItem");

    LocateResponseBatchItem result(item);
    result.locatePayload_ = LocateResponsePayload::fromElement(
        detail::require_response_payload(item, "LocateResponseBatchItem")
    );
    return result;
  }

}  // namespace kmipcore
