#include "kmipcore/attributes_parser.hpp"

#include "kmipcore/kmip_attribute_names.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace kmipcore {

  namespace {


    [[nodiscard]] std::string attribute_key_from_name(const std::string &name) {
      if (name == "Name") return KMIP_ATTR_NAME_NAME;
      if (name == "Object Group") return KMIP_ATTR_NAME_GROUP;
      if (name == "State") return KMIP_ATTR_NAME_STATE;
      if (name == "Unique Identifier") return KMIP_ATTR_NAME_UNIQUE_IDENTIFIER;
      if (name == "UniqueID") return KMIP_ATTR_NAME_UNIQUE_IDENTIFIER;  // Legacy/PyKMIP compat
      if (name == "Initial Date") return KMIP_ATTR_NAME_INITIAL_DATE;
      if (name == "Activation Date") return KMIP_ATTR_NAME_ACTIVATION_DATE;
      if (name == "Process Start Date") return KMIP_ATTR_NAME_PROCESS_START_DATE;
      if (name == "Protect Stop Date") return KMIP_ATTR_NAME_PROTECT_STOP_DATE;
      if (name == "Deactivation Date") return KMIP_ATTR_NAME_DEACTIVATION_DATE;
      if (name == "Destroy Date") return KMIP_ATTR_NAME_DESTROY_DATE;
      if (name == "Compromise Occurrence Date") return KMIP_ATTR_NAME_COMPROMISE_OCCURRENCE_DATE;
      if (name == "Compromise Date") return KMIP_ATTR_NAME_COMPROMISE_DATE;
      if (name == "Archive Date") return KMIP_ATTR_NAME_ARCHIVE_DATE;
      if (name == "Last Change Date") return KMIP_ATTR_NAME_LAST_CHANGE_DATE;
      if (name == "Cryptographic Algorithm") return KMIP_ATTR_NAME_CRYPTO_ALG;
      if (name == "Cryptographic Length") return KMIP_ATTR_NAME_CRYPTO_LEN;
      if (name == "Cryptographic Usage Mask") return KMIP_ATTR_NAME_CRYPTO_USAGE_MASK;
      if (name == "Contact Information") return KMIP_ATTR_NAME_CONTACT_INFO;
      if (name == "Operation Policy Name") return KMIP_ATTR_NAME_OPERATION_POLICY_NAME;
      return name;
    }

    [[nodiscard]] std::string crypto_alg_to_string(int32_t val) {
      switch (val) {
        case KMIP_CRYPTOALG_DES: return "DES";
        case KMIP_CRYPTOALG_TRIPLE_DES: return "3DES";
        case KMIP_CRYPTOALG_AES: return "AES";
        case KMIP_CRYPTOALG_RSA: return "RSA";
        case KMIP_CRYPTOALG_DSA: return "DSA";
        case KMIP_CRYPTOALG_ECDSA: return "ECDSA";
        case KMIP_CRYPTOALG_HMAC_SHA1: return "HMAC-SHA1";
        case KMIP_CRYPTOALG_HMAC_SHA224: return "HMAC-SHA224";
        case KMIP_CRYPTOALG_HMAC_SHA256: return "HMAC-SHA256";
        case KMIP_CRYPTOALG_HMAC_SHA384: return "HMAC-SHA384";
        case KMIP_CRYPTOALG_HMAC_SHA512: return "HMAC-SHA512";
        case KMIP_CRYPTOALG_HMAC_MD5: return "HMAC-MD5";
        case KMIP_CRYPTOALG_DH: return "DH";
        case KMIP_CRYPTOALG_ECDH: return "ECDH";
        default: return std::to_string(val);
      }
    }

    [[nodiscard]] std::string date_to_string(int64_t seconds) {
      // Return ISO 8601 format or similar "YYYY-MM-DD HH:MM:SS"
      // KMIP Date-Time is standard UNIX epoch seconds.
      std::time_t t = static_cast<std::time_t>(seconds);
      std::tm tm_buf{};
#ifdef _WIN32
      gmtime_s(&tm_buf, &t);
#else
      gmtime_r(&t, &tm_buf);
#endif
      std::ostringstream oss;
      oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
      return oss.str();
    }

    [[nodiscard]] std::string parse_attribute_value(
        const std::string &attribute_name, const std::shared_ptr<Element> &value
    ) {
      if (!value) {
        return {};
      }

      switch (value->type) {
        case KMIP_TYPE_TEXT_STRING:
          return value->toString();
        case KMIP_TYPE_INTEGER:
          return std::to_string(value->toInt());
        case KMIP_TYPE_DATE_TIME:
          return date_to_string(value->toLong());
        case KMIP_TYPE_LONG_INTEGER:
          return std::to_string(value->toLong());
        case KMIP_TYPE_ENUMERATION:
          if (attribute_name == KMIP_ATTR_NAME_STATE) {
            return state_to_string(value->toEnum());
          }
          if (attribute_name == KMIP_ATTR_NAME_CRYPTO_ALG) {
            return crypto_alg_to_string(value->toEnum());
          }
          return std::to_string(value->toEnum());
        case KMIP_TYPE_STRUCTURE:
          if (attribute_name == KMIP_ATTR_NAME_NAME) {
            if (auto name_value =
                    value->getChild(static_cast<Tag>(KMIP_TAG_NAME_VALUE));
                name_value) {
              return name_value->toString();
            }
          }
          break;
        default:
          break;
      }

      return {};
    }

  }  // namespace

  attributes_t AttributesParser::parse(
      const std::vector<std::shared_ptr<Element>> &attributes
  ) {
    attributes_t res;
    for (const auto &attribute : attributes) {
      if (attribute == nullptr ||
          attribute->tag != static_cast<Tag>(KMIP_TAG_ATTRIBUTE)) {
        continue;
      }

      auto attribute_name =
          attribute->getChild(static_cast<Tag>(KMIP_TAG_ATTRIBUTE_NAME));
      auto attribute_value =
          attribute->getChild(static_cast<Tag>(KMIP_TAG_ATTRIBUTE_VALUE));
      if (!attribute_name) {
        continue;
      }

      const auto name = attribute_name->toString();
      res[attribute_key_from_name(name)] =
          parse_attribute_value(name, attribute_value);
    }
    return res;
  }

}  // namespace kmipcore
