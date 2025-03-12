#include "kmipcore/kmip_formatter.hpp"

#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/kmip_protocol.hpp"
#include "kmipcore/types.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace kmipcore {

  namespace {

    [[nodiscard]] std::string indent(size_t level) {
      return std::string(level * 2, ' ');
    }

    [[nodiscard]] std::string format_hex_uint(uint64_t value, size_t width = 0) {
      std::ostringstream oss;
      oss << "0x" << std::uppercase << std::hex << std::setfill('0');
      if (width > 0) {
        oss << std::setw(static_cast<int>(width));
      }
      oss << value;
      return oss.str();
    }

    [[nodiscard]] std::string format_bytes_hex(std::span<const uint8_t> bytes) {
      std::ostringstream oss;
      oss << std::uppercase << std::hex << std::setfill('0');
      for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) {
          oss << ' ';
        }
        oss << std::setw(2) << static_cast<int>(bytes[i]);
      }
      return oss.str();
    }

    [[nodiscard]] std::string quote_string(const std::string &value) {
      std::ostringstream oss;
      oss << '"';
      for (const char ch : value) {
        switch (ch) {
          case '\\':
            oss << "\\\\";
            break;
          case '"':
            oss << "\\\"";
            break;
          case '\n':
            oss << "\\n";
            break;
          case '\r':
            oss << "\\r";
            break;
          case '\t':
            oss << "\\t";
            break;
          default:
            oss << ch;
            break;
        }
      }
      oss << '"';
      return oss.str();
    }

    [[nodiscard]] std::string format_datetime(int64_t seconds) {
      std::time_t t = static_cast<std::time_t>(seconds);
      std::tm tm_buf{};
#if defined(_WIN32)
      gmtime_s(&tm_buf, &t);
#else
      gmtime_r(&t, &tm_buf);
#endif
      std::ostringstream oss;
      oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ") << " (" << seconds
          << ')';
      return oss.str();
    }

    [[nodiscard]] const char *type_name(Type type) {
      switch (type) {
        case KMIP_TYPE_STRUCTURE:
          return "Structure";
        case KMIP_TYPE_INTEGER:
          return "Integer";
        case KMIP_TYPE_LONG_INTEGER:
          return "LongInteger";
        case KMIP_TYPE_BIG_INTEGER:
          return "BigInteger";
        case KMIP_TYPE_ENUMERATION:
          return "Enumeration";
        case KMIP_TYPE_BOOLEAN:
          return "Boolean";
        case KMIP_TYPE_TEXT_STRING:
          return "TextString";
        case KMIP_TYPE_BYTE_STRING:
          return "ByteString";
        case KMIP_TYPE_DATE_TIME:
          return "DateTime";
        case KMIP_TYPE_INTERVAL:
          return "Interval";
        case KMIP_TYPE_DATE_TIME_EXTENDED:
          return "DateTimeExtended";
        default:
          return "UnknownType";
      }
    }

    [[nodiscard]] const char *tag_name(Tag tag) {
      switch (tag) {
        case KMIP_TAG_ATTRIBUTE:
          return "Attribute";
        case KMIP_TAG_ATTRIBUTE_NAME:
          return "AttributeName";
        case KMIP_TAG_ATTRIBUTE_VALUE:
          return "AttributeValue";
        case KMIP_TAG_BATCH_COUNT:
          return "BatchCount";
        case KMIP_TAG_BATCH_ITEM:
          return "BatchItem";
        case KMIP_TAG_BATCH_ORDER_OPTION:
          return "BatchOrderOption";
        case KMIP_TAG_COMPROMISE_OCCURRANCE_DATE:
          return "CompromiseOccurrenceDate";
        case KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
          return "CryptographicAlgorithm";
        case KMIP_TAG_CRYPTOGRAPHIC_LENGTH:
          return "CryptographicLength";
        case KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK:
          return "CryptographicUsageMask";
        case KMIP_TAG_KEY_BLOCK:
          return "KeyBlock";
        case KMIP_TAG_KEY_FORMAT_TYPE:
          return "KeyFormatType";
        case KMIP_TAG_KEY_MATERIAL:
          return "KeyMaterial";
        case KMIP_TAG_KEY_VALUE:
          return "KeyValue";
        case KMIP_TAG_LOCATED_ITEMS:
          return "LocatedItems";
        case KMIP_TAG_MAXIMUM_ITEMS:
          return "MaximumItems";
        case KMIP_TAG_MAXIMUM_RESPONSE_SIZE:
          return "MaximumResponseSize";
        case KMIP_TAG_NAME:
          return "Name";
        case KMIP_TAG_NAME_TYPE:
          return "NameType";
        case KMIP_TAG_NAME_VALUE:
          return "NameValue";
        case KMIP_TAG_OBJECT_GROUP:
          return "ObjectGroup";
        case KMIP_TAG_OBJECT_TYPE:
          return "ObjectType";
        case KMIP_TAG_OFFSET_ITEMS:
          return "OffsetItems";
        case KMIP_TAG_OPERATION:
          return "Operation";
        case KMIP_TAG_PROTOCOL_VERSION:
          return "ProtocolVersion";
        case KMIP_TAG_PROTOCOL_VERSION_MAJOR:
          return "ProtocolVersionMajor";
        case KMIP_TAG_PROTOCOL_VERSION_MINOR:
          return "ProtocolVersionMinor";
        case KMIP_TAG_REQUEST_HEADER:
          return "RequestHeader";
        case KMIP_TAG_REQUEST_MESSAGE:
          return "RequestMessage";
        case KMIP_TAG_REQUEST_PAYLOAD:
          return "RequestPayload";
        case KMIP_TAG_RESPONSE_HEADER:
          return "ResponseHeader";
        case KMIP_TAG_RESPONSE_MESSAGE:
          return "ResponseMessage";
        case KMIP_TAG_RESPONSE_PAYLOAD:
          return "ResponsePayload";
        case KMIP_TAG_RESULT_MESSAGE:
          return "ResultMessage";
        case KMIP_TAG_RESULT_REASON:
          return "ResultReason";
        case KMIP_TAG_RESULT_STATUS:
          return "ResultStatus";
        case KMIP_TAG_REVOKATION_MESSAGE:
          return "RevocationMessage";
        case KMIP_TAG_REVOCATION_REASON:
          return "RevocationReason";
        case KMIP_TAG_REVOCATION_REASON_CODE:
          return "RevocationReasonCode";
        case KMIP_TAG_SECRET_DATA:
          return "SecretData";
        case KMIP_TAG_SECRET_DATA_TYPE:
          return "SecretDataType";
        case KMIP_TAG_STATE:
          return "State";
        case KMIP_TAG_SYMMETRIC_KEY:
          return "SymmetricKey";
        case KMIP_TAG_TEMPLATE_ATTRIBUTE:
          return "TemplateAttribute";
        case KMIP_TAG_TIME_STAMP:
          return "TimeStamp";
        case KMIP_TAG_UNIQUE_BATCH_ITEM_ID:
          return "UniqueBatchItemId";
        case KMIP_TAG_UNIQUE_IDENTIFIER:
          return "UniqueIdentifier";
        case KMIP_TAG_USERNAME:
          return "Username";
        case KMIP_TAG_PASSWORD:
          return "Password";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *operation_name(int32_t value) {
      switch (value) {
        case KMIP_OP_CREATE:
          return "Create";
        case KMIP_OP_REGISTER:
          return "Register";
        case KMIP_OP_LOCATE:
          return "Locate";
        case KMIP_OP_GET:
          return "Get";
        case KMIP_OP_GET_ATTRIBUTES:
          return "GetAttributes";
        case KMIP_OP_GET_ATTRIBUTE_LIST:
          return "GetAttributeList";
        case KMIP_OP_ACTIVATE:
          return "Activate";
        case KMIP_OP_REVOKE:
          return "Revoke";
        case KMIP_OP_DESTROY:
          return "Destroy";
        case KMIP_OP_QUERY:
          return "Query";
        case KMIP_OP_DISCOVER_VERSIONS:
          return "DiscoverVersions";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *object_type_name(int32_t value) {
      switch (value) {
        case KMIP_OBJTYPE_CERTIFICATE:
          return "Certificate";
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
          return "SymmetricKey";
        case KMIP_OBJTYPE_PUBLIC_KEY:
          return "PublicKey";
        case KMIP_OBJTYPE_PRIVATE_KEY:
          return "PrivateKey";
        case KMIP_OBJTYPE_SECRET_DATA:
          return "SecretData";
        case KMIP_OBJTYPE_OPAQUE_OBJECT:
          return "OpaqueObject";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *result_status_name(int32_t value) {
      switch (value) {
        case KMIP_STATUS_SUCCESS:
          return "Success";
        case KMIP_STATUS_OPERATION_FAILED:
          return "OperationFailed";
        case KMIP_STATUS_OPERATION_PENDING:
          return "OperationPending";
        case KMIP_STATUS_OPERATION_UNDONE:
          return "OperationUndone";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *crypto_algorithm_name(int32_t value) {
      switch (value) {
        case KMIP_CRYPTOALG_DES:
          return "DES";
        case KMIP_CRYPTOALG_TRIPLE_DES:
          return "3DES";
        case KMIP_CRYPTOALG_AES:
          return "AES";
        case KMIP_CRYPTOALG_RSA:
          return "RSA";
        case KMIP_CRYPTOALG_DSA:
          return "DSA";
        case KMIP_CRYPTOALG_ECDSA:
          return "ECDSA";
        case KMIP_CRYPTOALG_HMAC_SHA1:
          return "HMAC-SHA1";
        case KMIP_CRYPTOALG_HMAC_SHA224:
          return "HMAC-SHA224";
        case KMIP_CRYPTOALG_HMAC_SHA256:
          return "HMAC-SHA256";
        case KMIP_CRYPTOALG_HMAC_SHA384:
          return "HMAC-SHA384";
        case KMIP_CRYPTOALG_HMAC_SHA512:
          return "HMAC-SHA512";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *name_type_name(int32_t value) {
      switch (value) {
        case KMIP_NAME_UNINTERPRETED_TEXT_STRING:
          return "UninterpretedTextString";
        case KMIP_NAME_URI:
          return "URI";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *key_format_type_name(int32_t value) {
      switch (value) {
        case KMIP_KEYFORMAT_RAW:
          return "Raw";
        case KMIP_KEYFORMAT_OPAQUE:
          return "Opaque";
        case KMIP_KEYFORMAT_PKCS1:
          return "PKCS1";
        case KMIP_KEYFORMAT_PKCS8:
          return "PKCS8";
        case KMIP_KEYFORMAT_X509:
          return "X509";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *secret_data_type_name(int32_t value) {
      switch (value) {
        case PASSWORD:
          return "Password";
        case SEED:
          return "Seed";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] const char *revocation_reason_name(int32_t value) {
      switch (value) {
        case UNSPECIFIED:
          return "Unspecified";
        case KEY_COMPROMISE:
          return "KeyCompromise";
        case CA_COMPROMISE:
          return "CACompromise";
        case AFFILIATION_CHANGED:
          return "AffiliationChanged";
        case SUSPENDED:
          return "Suspended";
        case CESSATION_OF_OPERATION:
          return "CessationOfOperation";
        case PRIVILEDGE_WITHDRAWN:
          return "PrivilegeWithdrawn";
        case REVOCATION_EXTENSIONS:
          return "Extensions";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] std::string enum_value_name(Tag tag, int32_t value) {
      const char *name = nullptr;
      switch (tag) {
        case KMIP_TAG_OPERATION:
          name = operation_name(value);
          break;
        case KMIP_TAG_OBJECT_TYPE:
          name = object_type_name(value);
          break;
        case KMIP_TAG_RESULT_STATUS:
          name = result_status_name(value);
          break;
        case KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
          name = crypto_algorithm_name(value);
          break;
        case KMIP_TAG_NAME_TYPE:
          name = name_type_name(value);
          break;
        case KMIP_TAG_KEY_FORMAT_TYPE:
          name = key_format_type_name(value);
          break;
        case KMIP_TAG_SECRET_DATA_TYPE:
          name = secret_data_type_name(value);
          break;
        case KMIP_TAG_STATE:
          name = state_to_string(value);
          break;
        case KMIP_TAG_REVOCATION_REASON_CODE:
          name = revocation_reason_name(value);
          break;
        default:
          break;
      }

      if (name != nullptr) {
        std::ostringstream oss;
        oss << name << " (" << value << ')';
        return oss.str();
      }

      std::ostringstream oss;
      oss << value << " / " << format_hex_uint(static_cast<uint32_t>(value), 8);
      return oss.str();
    }

    void format_element_impl(
        const std::shared_ptr<Element> &element,
        std::ostringstream &oss,
        size_t depth
    ) {
      if (!element) {
        oss << indent(depth) << "<null>\n";
        return;
      }

      const char *known_tag_name = tag_name(element->tag);
      oss << indent(depth)
          << (known_tag_name != nullptr ? known_tag_name : "UnknownTag")
          << " (" << format_hex_uint(static_cast<uint32_t>(element->tag), 6)
          << ") [" << type_name(element->type) << ']';

      if (const auto *structure = element->asStructure(); structure != nullptr) {
        oss << '\n';
        if (structure->items.empty()) {
          oss << indent(depth + 1) << "<empty>\n";
        }
        for (const auto &child : structure->items) {
          format_element_impl(child, oss, depth + 1);
        }
        return;
      }

      oss << " = ";
      switch (element->type) {
        case KMIP_TYPE_INTEGER:
          oss << element->toInt();
          break;
        case KMIP_TYPE_LONG_INTEGER:
          oss << element->toLong();
          break;
        case KMIP_TYPE_BIG_INTEGER: {
          const auto value = element->toBytes();
          oss << "len=" << value.size() << ", hex=["
              << format_bytes_hex(std::span<const uint8_t>(value.data(), value.size()))
              << ']';
          break;
        }
        case KMIP_TYPE_ENUMERATION:
          oss << enum_value_name(element->tag, element->toEnum());
          break;
        case KMIP_TYPE_BOOLEAN:
          oss << (element->toBool() ? "true" : "false");
          break;
        case KMIP_TYPE_TEXT_STRING:
          oss << quote_string(element->toString());
          break;
        case KMIP_TYPE_BYTE_STRING: {
          const auto value = element->toBytes();
          oss << "len=" << value.size() << ", hex=["
              << format_bytes_hex(std::span<const uint8_t>(value.data(), value.size()))
              << ']';
          break;
        }
        case KMIP_TYPE_DATE_TIME:
          oss << format_datetime(element->toLong());
          break;
        case KMIP_TYPE_INTERVAL:
          oss << element->toInt();
          break;
        default:
          oss << "<unhandled>";
          break;
      }
      oss << '\n';
    }

  }  // namespace

  std::string format_element(const std::shared_ptr<Element> &element) {
    std::ostringstream oss;
    format_element_impl(element, oss, 0);
    return oss.str();
  }

  std::string format_request(const RequestMessage &request) {
    return format_element(request.toElement());
  }

  std::string format_response(const ResponseMessage &response) {
    return format_element(response.toElement());
  }

  std::string format_ttlv(std::span<const uint8_t> ttlv) {
    try {
      if (ttlv.empty()) {
        return "<empty KMIP TTLV>\n";
      }

      size_t offset = 0;
      auto root = Element::deserialize(ttlv, offset);
      auto formatted = format_element(root);
      if (offset != ttlv.size()) {
        std::ostringstream oss;
        oss << formatted
            << "Trailing bytes: " << (ttlv.size() - offset) << "\n";
        return oss.str();
      }
      return formatted;
    } catch (const std::exception &e) {
      std::ostringstream oss;
      oss << "Unable to format KMIP TTLV: " << e.what() << "\n"
          << "Raw bytes: [" << format_bytes_hex(ttlv) << "]\n";
      return oss.str();
    }
  }

}  // namespace kmipcore



