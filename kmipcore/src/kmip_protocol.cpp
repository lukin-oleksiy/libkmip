#include "kmipcore/kmip_protocol.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <cstring>
#include <ctime>
#include <vector>
namespace kmipcore {

  // === ProtocolVersion ===
  ProtocolVersion::ProtocolVersion(int32_t major, int32_t minor)
    : major_(major), minor_(minor) {}
  std::shared_ptr<Element> ProtocolVersion::toElement() const {
    auto structure =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_PROTOCOL_VERSION));
    structure->asStructure()->add(
        Element::createInteger(
            static_cast<Tag>(KMIP_TAG_PROTOCOL_VERSION_MAJOR), major_
        )
    );
    structure->asStructure()->add(
        Element::createInteger(
            static_cast<Tag>(KMIP_TAG_PROTOCOL_VERSION_MINOR), minor_
        )
    );
    return structure;
  }
  ProtocolVersion
      ProtocolVersion::fromElement(std::shared_ptr<Element> element) {
    if (!element ||
        element->tag != static_cast<Tag>(KMIP_TAG_PROTOCOL_VERSION) ||
        element->type != ::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid ProtocolVersion element");
    }
    ProtocolVersion pv;
    auto maj =
        element->getChild(static_cast<Tag>(KMIP_TAG_PROTOCOL_VERSION_MAJOR));
    if (maj) {
      pv.major_ = maj->toInt();
    }
    auto min =
        element->getChild(static_cast<Tag>(KMIP_TAG_PROTOCOL_VERSION_MINOR));
    if (min) {
      pv.minor_ = min->toInt();
    }
    return pv;
  }
  // === RequestHeader ===
  std::shared_ptr<Element> RequestHeader::toElement() const {
    auto structure =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_REQUEST_HEADER));
    structure->asStructure()->add(protocolVersion_.toElement());
    if (maximumResponseSize_) {
      structure->asStructure()->add(
          Element::createInteger(
              static_cast<Tag>(KMIP_TAG_MAXIMUM_RESPONSE_SIZE),
              *maximumResponseSize_
          )
      );
    }
    if (batchOrderOption_) {
      structure->asStructure()->add(
          Element::createBoolean(
              static_cast<Tag>(KMIP_TAG_BATCH_ORDER_OPTION), *batchOrderOption_
          )
      );
    }
    if (timeStamp_) {
      structure->asStructure()->add(
          Element::createDateTime(
              static_cast<Tag>(KMIP_TAG_TIME_STAMP), *timeStamp_
          )
      );
    }
    structure->asStructure()->add(
        Element::createInteger(
            static_cast<Tag>(KMIP_TAG_BATCH_COUNT), batchCount_
        )
    );
    return structure;
  }
  RequestHeader RequestHeader::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != static_cast<Tag>(KMIP_TAG_REQUEST_HEADER) ||
        element->type != ::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid RequestHeader element");
    }
    RequestHeader rh;
    auto pv = element->getChild(static_cast<Tag>(KMIP_TAG_PROTOCOL_VERSION));
    if (pv) {
      rh.protocolVersion_ = ProtocolVersion::fromElement(pv);
    } else {
      throw KmipException("Missing ProtocolVersion in header");
    }
    auto maxResponseSize =
        element->getChild(static_cast<Tag>(KMIP_TAG_MAXIMUM_RESPONSE_SIZE));
    if (maxResponseSize) {
      rh.maximumResponseSize_ = maxResponseSize->toInt();
    }
    auto timeStamp = element->getChild(static_cast<Tag>(KMIP_TAG_TIME_STAMP));
    if (timeStamp) {
      rh.timeStamp_ = timeStamp->toLong();
    }
    auto batchOrderOption =
        element->getChild(static_cast<Tag>(KMIP_TAG_BATCH_ORDER_OPTION));
    if (batchOrderOption) {
      rh.batchOrderOption_ = batchOrderOption->toBool();
    }
    auto bc = element->getChild(static_cast<Tag>(KMIP_TAG_BATCH_COUNT));
    if (bc) {
      rh.batchCount_ = bc->toInt();
    }
    return rh;
  }
  // === RequestBatchItem ===
  std::shared_ptr<Element> RequestBatchItem::toElement() const {
    auto structure =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_BATCH_ITEM));
    structure->asStructure()->add(
        Element::createEnumeration(
            static_cast<Tag>(KMIP_TAG_OPERATION), operation_
        )
    );
    if (uniqueBatchItemId_ != 0) {
      std::vector<uint8_t> idBytes(sizeof(uniqueBatchItemId_));
      std::memcpy(
          idBytes.data(), &uniqueBatchItemId_, sizeof(uniqueBatchItemId_)
      );
      structure->asStructure()->add(
          Element::createByteString(
              static_cast<Tag>(KMIP_TAG_UNIQUE_BATCH_ITEM_ID), idBytes
          )
      );
    }
    if (requestPayload_) {
      structure->asStructure()->add(requestPayload_);
    }
    return structure;
  }
  RequestBatchItem
      RequestBatchItem::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != static_cast<Tag>(KMIP_TAG_BATCH_ITEM) ||
        element->type != ::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid RequestBatchItem element");
    }
    RequestBatchItem rbi;
    auto op = element->getChild(static_cast<Tag>(KMIP_TAG_OPERATION));
    if (op) {
      rbi.operation_ = op->toEnum();
    } else {
      throw KmipException("Missing Operation");
    }
    auto id =
        element->getChild(static_cast<Tag>(KMIP_TAG_UNIQUE_BATCH_ITEM_ID));
    if (id) {
      auto bytes = id->toBytes();
      if (bytes.size() == sizeof(rbi.uniqueBatchItemId_)) {
        std::memcpy(
            &rbi.uniqueBatchItemId_,
            bytes.data(),
            sizeof(rbi.uniqueBatchItemId_)
        );
      }
    }
    auto payload =
        element->getChild(static_cast<Tag>(KMIP_TAG_REQUEST_PAYLOAD));
    if (payload) {
      rbi.requestPayload_ = payload;
    }
    return rbi;
  }
  // === RequestMessage ===
  RequestMessage::RequestMessage()
    : RequestMessage(DEFAULT_PROTOCOL_VERSION, DEFAULT_MAX_RESPONSE_SIZE) {}

  RequestMessage::RequestMessage(int32_t protocolVersionMinor)
    : RequestMessage(protocolVersionMinor, DEFAULT_MAX_RESPONSE_SIZE) {}

  RequestMessage::RequestMessage(
      int32_t protocolVersionMinor, size_t maxResponseSize
  ) {
    setProtocolVersionMinor(protocolVersionMinor);
    setMaxResponseSize(maxResponseSize);
  }

  uint32_t RequestMessage::add_batch_item(RequestBatchItem item) {
    const auto id = nextBatchItemId_++;
    item.setUniqueBatchItemId(id);
    batchItems_.push_back(std::move(item));
    return id;
  }

  void RequestMessage::setBatchItems(
      const std::vector<RequestBatchItem> &items
  ) {
    clearBatchItems();
    for (const auto &item : items) {
      add_batch_item(item);
    }
  }

  void RequestMessage::setProtocolVersionMinor(int32_t minor) {
    ProtocolVersion version = header_.getProtocolVersion();
    version.setMajor(1);
    version.setMinor(minor);
    header_.setProtocolVersion(version);
  }

  int32_t RequestMessage::getProtocolVersionMinor() const {
    return header_.getProtocolVersion().getMinor();
  }

  void RequestMessage::setMaxResponseSize(size_t size) {
    header_.setMaximumResponseSize(static_cast<int32_t>(size));
  }

  size_t RequestMessage::getMaxResponseSize() const {
    auto maxResponseSize = header_.getMaximumResponseSize();
    return maxResponseSize ? static_cast<size_t>(*maxResponseSize)
                           : DEFAULT_MAX_RESPONSE_SIZE;
  }

  std::vector<uint8_t> RequestMessage::serialize() const {
    if (batchItems_.empty()) {
      throw KmipException("Cannot serialize RequestMessage with no batch items");
    }

    RequestMessage request(*this);
    request.header_.setBatchCount(
        static_cast<int32_t>(request.batchItems_.size())
    );
    if (!request.header_.getBatchOrderOption().has_value()) {
      request.header_.setBatchOrderOption(true);
    }
    request.header_.setTimeStamp(static_cast<int64_t>(time(nullptr)));

    // Use SerializationBuffer for efficient serialization
    SerializationBuffer buf(request.getMaxResponseSize());
    request.toElement()->serialize(buf);
    return buf.release();
  }

  std::shared_ptr<Element> RequestMessage::toElement() const {
    auto structure =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_REQUEST_MESSAGE));
    structure->asStructure()->add(header_.toElement());
    for (const auto &item : batchItems_) {
      structure->asStructure()->add(item.toElement());
    }
    return structure;
  }
  RequestMessage RequestMessage::fromElement(std::shared_ptr<Element> element) {
    if (!element ||
        element->tag != static_cast<Tag>(KMIP_TAG_REQUEST_MESSAGE) ||
        element->type != ::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid RequestMessage element");
    }
    RequestMessage rm;
    auto hdr = element->getChild(static_cast<Tag>(KMIP_TAG_REQUEST_HEADER));
    if (hdr) {
      rm.header_ = RequestHeader::fromElement(hdr);
    } else {
      throw KmipException("Missing Request Header");
    }
    const auto *s = std::get_if<Structure>(&element->value);
    for (const auto &child : s->items) {
      if (child->tag == static_cast<Tag>(KMIP_TAG_BATCH_ITEM)) {
        rm.batchItems_.push_back(RequestBatchItem::fromElement(child));
      }
    }
    rm.nextBatchItemId_ = static_cast<uint32_t>(rm.batchItems_.size() + 1);
    return rm;
  }
  // === ResponseHeader ===
  std::shared_ptr<Element> ResponseHeader::toElement() const {
    auto structure =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_HEADER));
    structure->asStructure()->add(protocolVersion_.toElement());
    structure->asStructure()->add(
        Element::createDateTime(
            static_cast<Tag>(KMIP_TAG_TIME_STAMP), timeStamp_
        )
    );
    structure->asStructure()->add(
        Element::createInteger(
            static_cast<Tag>(KMIP_TAG_BATCH_COUNT), batchCount_
        )
    );
    return structure;
  }
  ResponseHeader ResponseHeader::fromElement(std::shared_ptr<Element> element) {
    if (!element ||
        element->tag != static_cast<Tag>(KMIP_TAG_RESPONSE_HEADER) ||
        element->type != ::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid ResponseHeader element");
    }
    ResponseHeader rh;
    auto pv = element->getChild(static_cast<Tag>(KMIP_TAG_PROTOCOL_VERSION));
    if (pv) {
      rh.protocolVersion_ = ProtocolVersion::fromElement(pv);
    } else {
      throw KmipException("Missing ProtocolVersion");
    }
    auto ts = element->getChild(static_cast<Tag>(KMIP_TAG_TIME_STAMP));
    if (ts) {
      rh.timeStamp_ = ts->toLong();
    }
    auto bc = element->getChild(static_cast<Tag>(KMIP_TAG_BATCH_COUNT));
    if (bc) {
      rh.batchCount_ = bc->toInt();
    }
    return rh;
  }
  // === ResponseBatchItem ===
  std::shared_ptr<Element> ResponseBatchItem::toElement() const {
    auto structure =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_BATCH_ITEM));
    structure->asStructure()->add(
        Element::createEnumeration(
            static_cast<Tag>(KMIP_TAG_OPERATION), operation_
        )
    );
    if (uniqueBatchItemId_ != 0) {
      std::vector<uint8_t> idBytes(sizeof(uniqueBatchItemId_));
      std::memcpy(
          idBytes.data(), &uniqueBatchItemId_, sizeof(uniqueBatchItemId_)
      );
      structure->asStructure()->add(
          Element::createByteString(
              static_cast<Tag>(KMIP_TAG_UNIQUE_BATCH_ITEM_ID), idBytes
          )
      );
    }
    structure->asStructure()->add(
        Element::createEnumeration(
            static_cast<Tag>(KMIP_TAG_RESULT_STATUS), resultStatus_
        )
    );
    if (resultReason_) {
      structure->asStructure()->add(
          Element::createEnumeration(
              static_cast<Tag>(KMIP_TAG_RESULT_REASON), *resultReason_
          )
      );
    }
    if (resultMessage_) {
      structure->asStructure()->add(
          Element::createTextString(
              static_cast<Tag>(KMIP_TAG_RESULT_MESSAGE), *resultMessage_
          )
      );
    }
    if (responsePayload_) {
      structure->asStructure()->add(responsePayload_);
    }
    return structure;
  }
  ResponseBatchItem
      ResponseBatchItem::fromElement(std::shared_ptr<Element> element) {
    if (!element || element->tag != static_cast<Tag>(KMIP_TAG_BATCH_ITEM) ||
        element->type != ::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid ResponseBatchItem element");
    }
    ResponseBatchItem rbi;
    auto op = element->getChild(static_cast<Tag>(KMIP_TAG_OPERATION));
    if (op) {
      rbi.operation_ = op->toEnum();
    }
    auto id =
        element->getChild(static_cast<Tag>(KMIP_TAG_UNIQUE_BATCH_ITEM_ID));
    if (id) {
      auto bytes = id->toBytes();
      if (bytes.size() == sizeof(rbi.uniqueBatchItemId_)) {
        std::memcpy(
            &rbi.uniqueBatchItemId_,
            bytes.data(),
            sizeof(rbi.uniqueBatchItemId_)
        );
      }
    }
    auto status = element->getChild(static_cast<Tag>(KMIP_TAG_RESULT_STATUS));
    if (status) {
      rbi.resultStatus_ = status->toEnum();
    }
    auto reason = element->getChild(static_cast<Tag>(KMIP_TAG_RESULT_REASON));
    if (reason) {
      rbi.resultReason_ = reason->toEnum();
    }
    auto msg = element->getChild(static_cast<Tag>(KMIP_TAG_RESULT_MESSAGE));
    if (msg) {
      rbi.resultMessage_ = msg->toString();
    }
    auto payload =
        element->getChild(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
    if (payload) {
      rbi.responsePayload_ = payload;
    }
    return rbi;
  }
  // === ResponseMessage ===
  std::shared_ptr<Element> ResponseMessage::toElement() const {
    auto structure =
        Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_MESSAGE));
    structure->asStructure()->add(header_.toElement());
    for (const auto &item : batchItems_) {
      structure->asStructure()->add(item.toElement());
    }
    return structure;
  }
  ResponseMessage
      ResponseMessage::fromElement(std::shared_ptr<Element> element) {
    if (!element ||
        element->tag != static_cast<Tag>(KMIP_TAG_RESPONSE_MESSAGE) ||
        element->type != ::KMIP_TYPE_STRUCTURE) {
      throw KmipException("Invalid ResponseMessage element");
    }
    ResponseMessage rm;
    auto hdr = element->getChild(static_cast<Tag>(KMIP_TAG_RESPONSE_HEADER));
    if (hdr) {
      rm.header_ = ResponseHeader::fromElement(hdr);
    }
    const auto *s = std::get_if<Structure>(&element->value);
    for (const auto &child : s->items) {
      if (child->tag == static_cast<Tag>(KMIP_TAG_BATCH_ITEM)) {
        rm.batchItems_.push_back(ResponseBatchItem::fromElement(child));
      }
    }
    return rm;
  }
}  // namespace kmipcore
