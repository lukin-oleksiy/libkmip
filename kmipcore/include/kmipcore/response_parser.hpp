#pragma once

#include "kmipcore/kmip_protocol.hpp"
#include "kmipcore/kmip_responses.hpp"

#include <span>
#include <string>
#include <vector>

namespace kmipcore {

  /** @brief Compact status summary for one KMIP response batch item. */
  struct OperationResult {
    /** Operation code reported by the response item. */
    int32_t operation = 0;
    /** KMIP result_status code. */
    int32_t resultStatus = 0;
    /** KMIP result_reason code when available. */
    int32_t resultReason = 0;
    /** Human-readable result message when available. */
    std::string resultMessage;
  };

  /** Parses KMIP response batch items and decodes typed operation-specific
   * items. */
  class ResponseParser {
  public:
    /**
     * @brief Creates a parser for one encoded KMIP response message.
     * @param responseBytes Raw TTLV response payload.
     */
    explicit ResponseParser(std::span<const uint8_t> responseBytes);
    /** @brief Default destructor. */
    ~ResponseParser() = default;
    ResponseParser(const ResponseParser &) = delete;
    ResponseParser(ResponseParser &&) = delete;
    ResponseParser &operator=(const ResponseParser &) = delete;
    ResponseParser &operator=(ResponseParser &&) = delete;

    /** @brief Returns number of batch items in the parsed response. */
    [[nodiscard]] size_t getBatchItemCount();
    /**
     * @brief Returns whether a batch item completed with KMIP_STATUS_SUCCESS.
     * @param itemIdx Zero-based batch item index.
     */
    [[nodiscard]] bool isSuccess(int itemIdx);

    /**
     * @brief Returns operation status fields for one batch item.
     * @param itemIdx Zero-based batch item index.
     */
    [[nodiscard]] OperationResult getOperationResult(int itemIdx);
    /**
     * @brief Returns operation status fields by unique batch item id.
     * @param batchItemId Request/response correlation id.
     */
    [[nodiscard]] OperationResult
        getOperationResultByBatchItemId(uint32_t batchItemId);

    /**
     * @brief Returns typed response object by index after success check.
     * @tparam TypedResponseBatchItem One of kmip_responses typed wrappers.
     * @param itemIdx Zero-based batch item index.
     * @throws KmipException if item is not successful or payload is invalid.
     */
    template<typename TypedResponseBatchItem>
    [[nodiscard]] TypedResponseBatchItem getResponse(int itemIdx) {
      const auto &item = getResponseItem(itemIdx);
      ensureSuccess(item);
      return TypedResponseBatchItem::fromBatchItem(item);
    }

    /**
     * @brief Returns typed response object by unique batch id after success check.
     * @tparam TypedResponseBatchItem One of kmip_responses typed wrappers.
     * @param batchItemId Request/response correlation id.
     * @throws KmipException if item is not successful or payload is invalid.
     */
    template<typename TypedResponseBatchItem>
    [[nodiscard]] TypedResponseBatchItem
        getResponseByBatchItemId(uint32_t batchItemId) {
      const auto &item = getResponseItemByBatchItemId(batchItemId);
      ensureSuccess(item);
      return TypedResponseBatchItem::fromBatchItem(item);
    }

  private:
    void parseResponse();

    void ensureParsed() {
      if (!isParsed_) {
        parseResponse();
      }
    }

    [[nodiscard]] const ResponseBatchItem &getResponseItem(int itemIdx);
    [[nodiscard]] const ResponseBatchItem &
        getResponseItemByBatchItemId(uint32_t batchItemId);

    static void ensureSuccess(const ResponseBatchItem &item);

    static std::string formatOperationResult(const ResponseBatchItem &value);
    static const char *operationToString(int32_t operation);
    static const char *resultStatusToString(int32_t status);

    std::vector<uint8_t> responseBytes_;
    ResponseMessage responseMessage_{};
    bool isParsed_ = false;
  };

}  // namespace kmipcore
