#include <cassert>
#include <iostream>
#include <kmipcore/kmip_basics.hpp>
#include <kmipcore/kmip_protocol.hpp>
#include <kmipcore/kmip_responses.hpp>
#include <kmipcore/serialization_buffer.hpp>
using namespace kmipcore;
void test_integer() {
  auto elem =
      Element::createInteger(static_cast<Tag>(KMIP_TAG_ACTIVATION_DATE), 12345);
  SerializationBuffer buf_i;
  elem->serialize(buf_i);
  auto data = buf_i.release();
  assert(data.size() == 16);
  size_t offset = 0;
  auto decoded = Element::deserialize(data, offset);
  assert(offset == 16);
  assert(decoded->tag == static_cast<Tag>(KMIP_TAG_ACTIVATION_DATE));
  assert(decoded->type == ::KMIP_TYPE_INTEGER);
  assert(std::get<Integer>(decoded->value).value == 12345);
  std::cout << "Integer test passed" << std::endl;
}
void test_structure() {
  auto root =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_APPLICATION_DATA));
  auto child1 = Element::createInteger(
      static_cast<Tag>(KMIP_TAG_APPLICATION_NAMESPACE), 10
  );
  auto child2 = Element::createBoolean(
      static_cast<Tag>(KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION), true
  );
  std::get<Structure>(root->value).add(child1);
  std::get<Structure>(root->value).add(child2);
  SerializationBuffer buf_s;
  root->serialize(buf_s);
  auto data = buf_s.release();
  size_t offset = 0;
  auto decoded = Element::deserialize(data, offset);
  assert(decoded->tag == static_cast<Tag>(KMIP_TAG_APPLICATION_DATA));
  assert(decoded->type == ::KMIP_TYPE_STRUCTURE);
  auto &s = std::get<Structure>(decoded->value);
  assert(s.items.size() == 2);
  auto d1 = s.items[0];
  assert(d1->tag == static_cast<Tag>(KMIP_TAG_APPLICATION_NAMESPACE));
  assert(std::get<Integer>(d1->value).value == 10);
  auto d2 = s.items[1];
  assert(
      d2->tag == static_cast<Tag>(KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION)
  );
  assert(std::get<Boolean>(d2->value).value == true);
  std::cout << "Structure test passed" << std::endl;
}
void test_request_message() {
  RequestMessage req;
  req.getHeader().getProtocolVersion().setMajor(1);
  req.getHeader().getProtocolVersion().setMinor(4);
  req.getHeader().setBatchOrderOption(true);

  RequestBatchItem item;
  item.setOperation(KMIP_OP_GET);  // Some operation code
  // Fake payload
  auto payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_REQUEST_PAYLOAD));
  payload->asStructure()->add(
      Element::createInteger(static_cast<Tag>(KMIP_TAG_ACTIVATION_DATE), 999)
  );
  item.setRequestPayload(payload);
  auto first_id = req.add_batch_item(item);

  RequestBatchItem item2;
  item2.setOperation(KMIP_OP_GET_ATTRIBUTE_LIST);
  auto payload2 =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_REQUEST_PAYLOAD));
  payload2->asStructure()->add(
      Element::createInteger(static_cast<Tag>(KMIP_TAG_ACTIVATION_DATE), 111)
  );
  item2.setRequestPayload(payload2);
  auto second_id = req.add_batch_item(item2);

  assert(first_id == 1);
  assert(second_id == 2);
  assert(first_id != second_id);

  auto bytes = req.serialize();
  std::cout << "Serialized RequestMessage size: " << bytes.size() << std::endl;
  size_t offset = 0;
  auto deserialized = Element::deserialize(bytes, offset);
  auto req2 = RequestMessage::fromElement(deserialized);
  assert(req2.getHeader().getProtocolVersion().getMajor() == 1);
  assert(req2.getHeader().getBatchOrderOption().has_value());
  assert(req2.getHeader().getBatchOrderOption().value() == true);
  assert(req2.getBatchItems().size() == 2);
  assert(req2.getBatchItems()[0].getUniqueBatchItemId() == 1u);
  assert(req2.getBatchItems()[1].getUniqueBatchItemId() == 2u);
  assert(req2.getBatchItems()[0].getOperation() == KMIP_OP_GET);
  assert(req2.getBatchItems()[1].getOperation() == KMIP_OP_GET_ATTRIBUTE_LIST);
  std::cout << "RequestMessage test passed" << std::endl;
}
void test_response_message() {
  ResponseMessage resp;
  resp.getHeader().getProtocolVersion().setMajor(1);
  resp.getHeader().getProtocolVersion().setMinor(4);
  resp.getHeader().setTimeStamp(1678886400);  // 2023-03-15 or so
  resp.getHeader().setBatchCount(2);

  ResponseBatchItem get_item;
  get_item.setUniqueBatchItemId(0x01020304u);
  get_item.setOperation(KMIP_OP_GET);
  get_item.setResultStatus(KMIP_STATUS_SUCCESS);  // Success
  get_item.setResultMessage("OK");

  auto get_payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  get_payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "id-get-1"
      )
  );
  get_payload->asStructure()->add(
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
  auto key_value =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_KEY_VALUE));
  key_value->asStructure()->add(
      Element::createByteString(
          static_cast<Tag>(KMIP_TAG_KEY_MATERIAL), {0x10, 0x11, 0x12, 0x13}
      )
  );
  key_block->asStructure()->add(key_value);
  symmetric_key->asStructure()->add(key_block);
  get_payload->asStructure()->add(symmetric_key);
  get_item.setResponsePayload(get_payload);
  resp.add_batch_item(get_item);

  ResponseBatchItem locate_item;
  locate_item.setOperation(KMIP_OP_LOCATE);
  locate_item.setResultStatus(KMIP_STATUS_SUCCESS);
  auto locate_payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  locate_payload->asStructure()->add(
      Element::createInteger(static_cast<Tag>(KMIP_TAG_LOCATED_ITEMS), 2)
  );
  locate_payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "id-locate-1"
      )
  );
  locate_payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "id-locate-2"
      )
  );
  locate_item.setResponsePayload(locate_payload);
  resp.add_batch_item(locate_item);

  auto elem = resp.toElement();
  SerializationBuffer buf_r;
  elem->serialize(buf_r);
  auto bytes = buf_r.release();
  size_t offset = 0;
  auto deserialized = Element::deserialize(bytes, offset);
  auto resp2 = ResponseMessage::fromElement(deserialized);
  assert(resp2.getHeader().getTimeStamp() == 1678886400);
  assert(resp2.getBatchItems().size() == 2);
  assert(resp2.getBatchItems()[0].getResultStatus() == KMIP_STATUS_SUCCESS);
  assert(*resp2.getBatchItems()[0].getResultMessage() == "OK");
  assert(resp2.getBatchItems()[1].getOperation() == KMIP_OP_LOCATE);
  std::cout << "ResponseMessage test passed" << std::endl;
}
void test_typed_response_batch_items() {
  auto create_payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  create_payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "create-id"
      )
  );

  ResponseBatchItem create_item;
  create_item.setOperation(KMIP_OP_CREATE);
  create_item.setResultStatus(KMIP_STATUS_SUCCESS);
  create_item.setResponsePayload(create_payload);

  auto create_response = CreateResponseBatchItem::fromBatchItem(create_item);
  assert(create_response.getUniqueIdentifier() == "create-id");

  auto get_payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  get_payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "get-id"
      )
  );
  get_payload->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_OBJECT_TYPE), KMIP_OBJTYPE_SECRET_DATA
      )
  );
  auto secret_data =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_SECRET_DATA));
  auto key_block =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_KEY_BLOCK));
  auto key_value =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_KEY_VALUE));
  key_value->asStructure()->add(
      Element::createByteString(
          static_cast<Tag>(KMIP_TAG_KEY_MATERIAL), {0x61, 0x62}
      )
  );
  key_block->asStructure()->add(key_value);
  secret_data->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_SECRET_DATA_TYPE), PASSWORD
      )
  );
  secret_data->asStructure()->add(key_block);
  get_payload->asStructure()->add(secret_data);

  ResponseBatchItem get_item;
  get_item.setOperation(KMIP_OP_GET);
  get_item.setResultStatus(KMIP_STATUS_SUCCESS);
  get_item.setResponsePayload(get_payload);

  auto get_response = GetResponseBatchItem::fromBatchItem(get_item);
  assert(get_response.getUniqueIdentifier() == "get-id");
  assert(get_response.getObjectType() == KMIP_OBJTYPE_SECRET_DATA);
  assert(get_response.getObjectElement() != nullptr);

  auto attributes_payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  auto attribute =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_ATTRIBUTE));
  attribute->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), "State"
      )
  );
  attribute->asStructure()->add(
      Element::createEnumeration(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_VALUE), KMIP_STATE_ACTIVE
      )
  );
  attributes_payload->asStructure()->add(attribute);

  ResponseBatchItem attributes_item;
  attributes_item.setOperation(KMIP_OP_GET_ATTRIBUTES);
  attributes_item.setResultStatus(KMIP_STATUS_SUCCESS);
  attributes_item.setResponsePayload(attributes_payload);

  auto attributes_response =
      GetAttributesResponseBatchItem::fromBatchItem(attributes_item);
  assert(attributes_response.getAttributes().size() == 1);

  auto attribute_list_payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  attribute_list_payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), "Name"
      )
  );
  attribute_list_payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME), "State"
      )
  );

  ResponseBatchItem attribute_list_item;
  attribute_list_item.setOperation(KMIP_OP_GET_ATTRIBUTE_LIST);
  attribute_list_item.setResultStatus(KMIP_STATUS_SUCCESS);
  attribute_list_item.setResponsePayload(attribute_list_payload);

  auto attribute_list_response =
      GetAttributeListResponseBatchItem::fromBatchItem(attribute_list_item);
  assert(attribute_list_response.getAttributeNames().size() == 2);
  assert(attribute_list_response.getAttributeNames()[0] == "Name");

  auto locate_payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  locate_payload->asStructure()->add(
      Element::createInteger(static_cast<Tag>(KMIP_TAG_LOCATED_ITEMS), 2)
  );
  locate_payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "loc-1"
      )
  );
  locate_payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "loc-2"
      )
  );

  ResponseBatchItem locate_item;
  locate_item.setOperation(KMIP_OP_LOCATE);
  locate_item.setResultStatus(KMIP_STATUS_SUCCESS);
  locate_item.setResponsePayload(locate_payload);

  auto locate_response = LocateResponseBatchItem::fromBatchItem(locate_item);
  assert(locate_response.getLocatePayload().getLocatedItems().value() == 2);
  assert(locate_response.getUniqueIdentifiers().size() == 2);

  ResponseBatchItem destroy_item;
  destroy_item.setOperation(KMIP_OP_DESTROY);
  destroy_item.setResultStatus(KMIP_STATUS_SUCCESS);
  auto destroy_payload =
      Element::createStructure(static_cast<Tag>(KMIP_TAG_RESPONSE_PAYLOAD));
  destroy_payload->asStructure()->add(
      Element::createTextString(
          static_cast<Tag>(KMIP_TAG_UNIQUE_IDENTIFIER), "destroy-id"
      )
  );
  destroy_item.setResponsePayload(destroy_payload);

  auto destroy_response = DestroyResponseBatchItem::fromBatchItem(destroy_item);
  assert(destroy_response.getUniqueIdentifier() == "destroy-id");

  std::cout << "Typed response batch item tests passed" << std::endl;
}
void test_locate_payload() {
  LocateRequestPayload locReq;
  locReq.setMaximumItems(10);
  locReq.setOffsetItems(5);
  locReq.addAttribute(Attribute("Name", "Key1"));

  auto elem = locReq.toElement();
  SerializationBuffer buf_l;
  elem->serialize(buf_l);
  auto bytes = buf_l.release();

  size_t offset = 0;
  auto deserialized = Element::deserialize(bytes, offset);
  auto locReq2 = LocateRequestPayload::fromElement(deserialized);

  assert(locReq2.getMaximumItems() == 10);
  assert(locReq2.getOffsetItems() == 5);
  assert(locReq2.getAttributes().size() == 1);
  assert(locReq2.getAttributes()[0].getName() == "Name");

  std::cout << "Locate Payload test passed" << std::endl;
}
int main() {
  test_integer();
  test_structure();
  test_request_message();
  test_response_message();
  test_typed_response_batch_items();
  test_locate_payload();
  return 0;
}
