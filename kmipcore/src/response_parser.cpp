#include "kmipcore/response_parser.hpp"

#include <sstream>

namespace kmipcore {

  ResponseParser::ResponseParser(std::span<const uint8_t> responseBytes)
    : responseBytes_(responseBytes.begin(), responseBytes.end()) {}

  size_t ResponseParser::getBatchItemCount() {
    ensureParsed();
    return responseMessage_.getBatchItems().size();
  }

  bool ResponseParser::isSuccess(int itemIdx) {
    return getResponseItem(itemIdx).getResultStatus() == KMIP_STATUS_SUCCESS;
  }

  OperationResult ResponseParser::getOperationResult(int itemIdx) {
    const auto &item = getResponseItem(itemIdx);
    return OperationResult{
        item.getOperation(),
        item.getResultStatus(),
        item.getResultReason().value_or(0),
        item.getResultMessage().value_or("")
    };
  }

  OperationResult
      ResponseParser::getOperationResultByBatchItemId(uint32_t batchItemId) {
    const auto &item = getResponseItemByBatchItemId(batchItemId);
    return OperationResult{
        item.getOperation(),
        item.getResultStatus(),
        item.getResultReason().value_or(0),
        item.getResultMessage().value_or("")
    };
  }

  void ResponseParser::parseResponse() {
    if (responseBytes_.empty()) {
      throw KmipException("Empty response from the server.");
    }

    size_t offset = 0;
    auto root = Element::deserialize(
        std::span<const uint8_t>(responseBytes_.data(), responseBytes_.size()),
        offset
    );  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if (offset != responseBytes_.size()) {
      throw KmipException("Trailing bytes found after KMIP response message.");
    }

    responseMessage_ = ResponseMessage::fromElement(root);
    isParsed_ = true;
  }

  const ResponseBatchItem &ResponseParser::getResponseItem(int itemIdx) {
    ensureParsed();

    const auto &items = responseMessage_.getBatchItems();
    if (items.empty()) {
      throw KmipException("No response batch items from the server.");
    }
    if (itemIdx < 0 || static_cast<size_t>(itemIdx) >= items.size()) {
      throw KmipException("Response batch item index is out of range.");
    }

    return items[static_cast<size_t>(itemIdx)];
  }

  const ResponseBatchItem &
      ResponseParser::getResponseItemByBatchItemId(uint32_t batchItemId) {
    ensureParsed();

    const auto &items = responseMessage_.getBatchItems();
    for (const auto &item : items) {
      if (item.getUniqueBatchItemId() == batchItemId) {
        return item;
      }
    }

    throw KmipException("Response batch item id was not found.");
  }

  void ResponseParser::ensureSuccess(const ResponseBatchItem &item) {
    if (item.getResultStatus() != KMIP_STATUS_SUCCESS) {
      throw KmipException(formatOperationResult(item));
    }
  }

  std::string
      ResponseParser::formatOperationResult(const ResponseBatchItem &value) {
    OperationResult result = {
        value.getOperation(),
        value.getResultStatus(),
        value.getResultReason().value_or(0),
        value.getResultMessage().value_or("")
    };

    std::ostringstream stream;
    stream << "Message: " << result.resultMessage
           << "\nOperation: " << operationToString(result.operation)
           << "; Result status: " << resultStatusToString(result.resultStatus)
           << "; Result reason: " << result.resultReason;
    return stream.str();
  }

  const char *ResponseParser::operationToString(int32_t operation) {
    switch (operation) {
      case KMIP_OP_CREATE:
        return "Create";
      case KMIP_OP_REGISTER:
        return "Register";
      case KMIP_OP_GET:
        return "Get";
      case KMIP_OP_GET_ATTRIBUTES:
        return "Get Attributes";
      case KMIP_OP_ACTIVATE:
        return "Activate";
      case KMIP_OP_DESTROY:
        return "Destroy";
      case KMIP_OP_LOCATE:
        return "Locate";
      case KMIP_OP_REVOKE:
        return "Revoke";
      case KMIP_OP_GET_ATTRIBUTE_LIST:
        return "Get Attribute List";
      default:
        return "Unknown";
    }
  }

  const char *ResponseParser::resultStatusToString(int32_t status) {
    switch (status) {
      case KMIP_STATUS_SUCCESS:
        return "Success";
      case KMIP_STATUS_OPERATION_FAILED:
        return "Operation Failed";
      case KMIP_STATUS_OPERATION_PENDING:
        return "Operation Pending";
      case KMIP_STATUS_OPERATION_UNDONE:
        return "Operation Undone";
      default:
        return "Unknown";
    }
  }

}  // namespace kmipcore
