#include "kmipcore/attributes_parser.hpp"
#include "kmipcore/kmip_formatter.hpp"
#include "kmipcore/key_parser.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_logger.hpp"
#include "kmipcore/kmip_requests.hpp"
#include "kmipcore/response_parser.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <vector>

using namespace kmipcore;

namespace {

  class CollectingLogger : public Logger {
  public:
    [[nodiscard]] bool shouldLog(LogLevel level) const override {
      return level == LogLevel::Debug;
    }

    void log(const LogRecord &record) override { records.push_back(record); }

    std::vector<LogRecord> records;
  };

}  // namespace

// Helper to create a basic success response message with one item
std::vector<uint8_t> create_mock_response_bytes(
    int32_t operation, std::shared_ptr<Element> payload
) {
  ResponseMessage resp;
  resp.getHeader().getProtocolVersion().setMajor(1);
  resp.getHeader().getProtocolVersion().setMinor(4);
  resp.getHeader().setTimeStamp(1234567890);
  resp.getHeader().setBatchCount(1);

  ResponseBatchItem item;
  item.setUniqueBatchItemId(1);
  item.setOperation(operation);
  item.setResultStatus(KMIP_STATUS_SUCCESS);
  if (payload) {
    item.setResponsePayload(payload);
  }

  resp.add_batch_item(item);
  SerializationBuffer buf;
  resp.toElement()->serialize(buf);
  return buf.release();
}

void test_response_parser_create() {
  auto payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  payload->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_OBJECT_TYPE), KMIP_OBJTYPE_SYMMETRIC_KEY
      )
  );
  payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "uuid-1234"
      )
  );

  auto bytes = create_mock_response_bytes(KMIP_OP_CREATE, payload);
  ResponseParser parser(bytes);

  assert(parser.getBatchItemCount() == 1);
  assert(parser.isSuccess(0));

  auto result = parser.getOperationResult(0);
  assert(result.operation == KMIP_OP_CREATE);
  assert(result.resultStatus == KMIP_STATUS_SUCCESS);

  auto create_resp = parser.getResponse<CreateResponseBatchItem>(0);
  assert(create_resp.getUniqueIdentifier() == "uuid-1234");

  std::cout << "ResponseParser Create test passed" << std::endl;
}

void test_response_parser_locate() {
  auto payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  payload->asStructure()->add(
      Element::createInteger(static_cast<Tag>(KMIP_TAG_LOCATED_ITEMS), 2)
  );
  payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "uuid-1"
      )
  );
  payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "uuid-2"
      )
  );

  auto bytes = create_mock_response_bytes(KMIP_OP_LOCATE, payload);
  ResponseParser parser(bytes);

  auto locate_resp = parser.getResponse<LocateResponseBatchItem>(0);
  assert(locate_resp.getLocatePayload().getUniqueIdentifiers().size() == 2);
  assert(locate_resp.getUniqueIdentifiers()[0] == "uuid-1");
  assert(locate_resp.getUniqueIdentifiers()[1] == "uuid-2");

  std::cout << "ResponseParser Locate test passed" << std::endl;
}


void test_key_parser_symmetric() {
  // Construct a mock GetResponse with Symmetric Key
  auto payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "key-id"
      )
  );
  payload->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_OBJECT_TYPE), KMIP_OBJTYPE_SYMMETRIC_KEY
      )
  );

  auto symmetric_key =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_SYMMETRIC_KEY));
  auto key_block =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_KEY_BLOCK));

  key_block->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_KEY_FORMAT_TYPE), KMIP_KEYFORMAT_RAW
      )
  );
  key_block->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM), KMIP_CRYPTOALG_AES
      )
  );

  auto key_value =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_KEY_VALUE));
  std::vector<uint8_t> actual_key = {0xDE, 0xAD, 0xBE, 0xEF};
  key_value->asStructure()->add(
      Element::createByteString(
          static_cast<Tag>(KMIP_TAG_KEY_MATERIAL), actual_key
      )
  );

  key_block->asStructure()->add(key_value);
  symmetric_key->asStructure()->add(key_block);
  payload->asStructure()->add(symmetric_key);

  ResponseBatchItem item;
  item.setOperation(KMIP_OP_GET);
  item.setResultStatus(KMIP_STATUS_SUCCESS);
  item.setResponsePayload(payload);

  GetResponseBatchItem get_resp = GetResponseBatchItem::fromBatchItem(item);
  Key key = KeyParser::parseGetKeyResponse(get_resp);

  assert(key.algorithm() == KMIP_CRYPTOALG_AES);
  assert(key.value() == actual_key);

  std::cout << "KeyParser Symmetric Key test passed" << std::endl;
}

void test_key_parser_secret_binary() {
  auto payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "secret-id"
      )
  );
  payload->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_OBJECT_TYPE), KMIP_OBJTYPE_SECRET_DATA
      )
  );

  auto secret_data =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_SECRET_DATA));
  secret_data->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_SECRET_DATA_TYPE), PASSWORD
      )
  );

  auto key_block =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_KEY_BLOCK));
  key_block->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_KEY_FORMAT_TYPE), KMIP_KEYFORMAT_OPAQUE
      )
  );

  auto key_value =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_KEY_VALUE));
  const secret_t bytes = {'p', 'a', 's', 's', 0x00, 'x'};
  key_value->asStructure()->add(
      Element::createByteString(
          static_cast<Tag>(KMIP_TAG_KEY_MATERIAL),
          std::vector<uint8_t>(bytes.begin(), bytes.end())
      )
  );
  key_block->asStructure()->add(key_value);
  secret_data->asStructure()->add(key_block);
  payload->asStructure()->add(secret_data);

  ResponseBatchItem item;
  item.setOperation(KMIP_OP_GET);
  item.setResultStatus(KMIP_STATUS_SUCCESS);
  item.setResponsePayload(payload);

  GetResponseBatchItem get_resp = GetResponseBatchItem::fromBatchItem(item);
  Secret secret = KeyParser::parseGetSecretResponse(get_resp);

  assert(secret.secret_type == PASSWORD);
  assert(secret.value == bytes);
  assert(secret.as_text().size() == bytes.size());

  std::cout << "KeyParser Secret Binary test passed" << std::endl;
}

void test_register_secret_request_structure() {
  const secret_t secret = {'a', 'b', 0x00, 'c'};
  RegisterSecretRequest req("s-name", "s-group", secret, PASSWORD);

  auto payload = req.getRequestPayload();
  assert(payload != nullptr);

  auto object_type = payload->getChild(static_cast<Tag>(KMIP_TAG_OBJECT_TYPE));
  assert(object_type != nullptr);
  assert(object_type->toEnum() == KMIP_OBJTYPE_SECRET_DATA);

  auto secret_data = payload->getChild(static_cast<Tag>(KMIP_TAG_SECRET_DATA));
  assert(secret_data != nullptr);

  auto secret_type =
      secret_data->getChild(static_cast<Tag>(KMIP_TAG_SECRET_DATA_TYPE));
  assert(secret_type != nullptr);
  assert(secret_type->toEnum() == PASSWORD);

  auto key_block = secret_data->getChild(static_cast<Tag>(KMIP_TAG_KEY_BLOCK));
  assert(key_block != nullptr);

  auto key_format =
      key_block->getChild(static_cast<Tag>(KMIP_TAG_KEY_FORMAT_TYPE));
  assert(key_format != nullptr);
  assert(key_format->toEnum() == KMIP_KEYFORMAT_OPAQUE);

  // KMIP 1.4: Secret Data Key Block does not require algorithm/length.
  assert(
      key_block->getChild(static_cast<Tag>(KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM)) ==
      nullptr
  );
  assert(
      key_block->getChild(static_cast<Tag>(KMIP_TAG_CRYPTOGRAPHIC_LENGTH)) ==
      nullptr
  );

  auto key_value = key_block->getChild(static_cast<Tag>(KMIP_TAG_KEY_VALUE));
  assert(key_value != nullptr);
  auto key_material =
      key_value->getChild(static_cast<Tag>(KMIP_TAG_KEY_MATERIAL));
  assert(key_material != nullptr);
  auto parsed = key_material->toBytes();
  assert(parsed.size() == secret.size());
  assert(std::equal(parsed.begin(), parsed.end(), secret.begin()));

  std::cout << "RegisterSecretRequest structure test passed" << std::endl;
}

void test_attributes_parser() {
  std::vector<std::shared_ptr<Element>> attributes;

  auto attr1 = Element::createStructure(static_cast<Tag>(KMIP_TAG_ATTRIBUTE));
  attr1->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), "Name"
      )
  );
  attr1->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_VALUE), "MyKey"
      )
  );
  attributes.push_back(attr1);

  auto attr2 = Element::createStructure(static_cast<Tag>(KMIP_TAG_ATTRIBUTE));
  attr2->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), "Cryptographic Length"
      )
  );
  attr2->asStructure()->add(
      Element::createInteger(static_cast<Tag>(KMIP_TAG_ATTRIBUTE_VALUE), 256)
  );
  attributes.push_back(attr2);

  auto parsed_attrs = AttributesParser::parse(attributes);

  assert(parsed_attrs.count("Name"));
  assert(parsed_attrs.at("Name") == "MyKey");

  assert(parsed_attrs.count("Cryptographic Length"));
  assert(parsed_attrs.at("Cryptographic Length") == "256");

  std::cout << "AttributesParser test passed" << std::endl;
}

void test_attributes_parser_extended() {
  std::vector<std::shared_ptr<Element>> attributes;

  // Test Date attribute
  auto attr_date =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_ATTRIBUTE));
  attr_date->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), "Activation Date"
      )
  );
  attr_date->asStructure()->add(
      Element::createDateTime(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_VALUE), 1678886400
      )
  );  // 2023-03-15T13:20:00Z (approx)
  attributes.push_back(attr_date);

  // Test Crypto Algorithm Enum
  auto attr_alg =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_ATTRIBUTE));
  attr_alg->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), "Cryptographic Algorithm"
      )
  );
  attr_alg->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_VALUE), KMIP_CRYPTOALG_AES
      )
  );
  attributes.push_back(attr_alg);

  auto parsed_attrs = AttributesParser::parse(attributes);

  assert(parsed_attrs.count("Activation Date"));
  std::string date_str = parsed_attrs.at("Activation Date");
  assert(date_str.find("2023-03-15") != std::string::npos);

  assert(parsed_attrs.count("Cryptographic Algorithm"));
  assert(parsed_attrs.at("Cryptographic Algorithm") == "AES");

  std::cout << "AttributesParser Extended test passed" << std::endl;
}

void test_formatter_for_request_and_response() {
  RequestMessage request;
  request.add_batch_item(GetRequest("request-id-123"));

  auto formatted_request = format_request(request);
  assert(formatted_request.find("RequestMessage") != std::string::npos);
  assert(formatted_request.find("Operation") != std::string::npos);
  assert(formatted_request.find("Get") != std::string::npos);
  assert(formatted_request.find("request-id-123") != std::string::npos);

  auto payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  payload->asStructure()->add(
      Element::createInteger(static_cast<Tag>(KMIP_TAG_LOCATED_ITEMS), 2)
  );
  payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "uuid-1"
      )
  );
  payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "uuid-2"
      )
  );

  auto bytes = create_mock_response_bytes(KMIP_OP_LOCATE, payload);
  auto formatted_response = format_ttlv(bytes);
  assert(formatted_response.find("ResponseMessage") != std::string::npos);
  assert(formatted_response.find("Locate") != std::string::npos);
  assert(formatted_response.find("uuid-1") != std::string::npos);
  assert(formatted_response.find("uuid-2") != std::string::npos);

  std::cout << "KMIP formatter test passed" << std::endl;
}

void test_logger_interface() {
  CollectingLogger logger;
  assert(logger.shouldLog(LogLevel::Debug));
  assert(!logger.shouldLog(LogLevel::Info));

  logger.log(LogRecord{
      .level = LogLevel::Debug,
      .component = "kmip.protocol",
      .event = "request",
      .message = "formatted ttlv"
  });

  assert(logger.records.size() == 1);
  assert(logger.records[0].level == LogLevel::Debug);
  assert(logger.records[0].component == "kmip.protocol");
  assert(logger.records[0].event == "request");
  assert(logger.records[0].message == "formatted ttlv");
  assert(std::string(to_string(LogLevel::Debug)) == "DEBUG");

  std::cout << "Logger interface test passed" << std::endl;
}

int main() {
  test_response_parser_create();
  test_response_parser_locate();
  test_key_parser_symmetric();
  test_key_parser_secret_binary();
  test_register_secret_request_structure();
  test_attributes_parser();
  test_attributes_parser_extended();
  test_formatter_for_request_and_response();
  test_logger_interface();
  return 0;
}
