#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace kmipcore {

  // Helper functions for big-endian
  static uint32_t to_be32(uint32_t v) {
    return htonl(v);
  }
  static uint64_t to_be64(uint64_t v) {
    uint32_t high = htonl(v >> 32);
    uint32_t low = htonl(v & 0xFFFFFFFF);
    return ((uint64_t) low << 32) | high;
  }
  static uint32_t from_be32(uint32_t v) {
    return ntohl(v);
  }
  static uint64_t from_be64(uint64_t v) {
    uint32_t high = ntohl(v >> 32);
    uint32_t low = ntohl(v & 0xFFFFFFFF);
    return ((uint64_t) high << 32) | low;
  }


  void Element::serialize(SerializationBuffer& buf) const {
    // Write Tag (3 bytes, big-endian)
    buf.writeByte((tag >> 16) & 0xFF);
    buf.writeByte((tag >> 8) & 0xFF);
    buf.writeByte(tag & 0xFF);

    // Write Type (1 byte)
    buf.writeByte(static_cast<uint8_t>(type));

    // First pass: calculate content and payload length
    SerializationBuffer content_buf;
    uint32_t payload_length = 0;

    if (std::holds_alternative<Structure>(value)) {
      const auto &s = std::get<Structure>(value);
      for (const auto &item : s.items) {
        item->serialize(content_buf);  // Recursive call
      }
      payload_length = content_buf.size();
    } else if (std::holds_alternative<Integer>(value)) {
      int32_t v = std::get<Integer>(value).value;
      v = to_be32(v);
      content_buf.writeBytes(&v, sizeof(v));
      payload_length = 4;
    } else if (std::holds_alternative<LongInteger>(value)) {
      int64_t v = std::get<LongInteger>(value).value;
      v = to_be64(v);
      content_buf.writeBytes(&v, sizeof(v));
      payload_length = 8;
    } else if (std::holds_alternative<BigInteger>(value)) {
      const auto &v = std::get<BigInteger>(value).value;
      content_buf.writeBytes(v.data(), v.size());
      payload_length = v.size();
    } else if (std::holds_alternative<Enumeration>(value)) {
      int32_t v = std::get<Enumeration>(value).value;
      v = to_be32(v);
      content_buf.writeBytes(&v, sizeof(v));
      payload_length = 4;
    } else if (std::holds_alternative<Boolean>(value)) {
      uint64_t v = std::get<Boolean>(value).value ? 1 : 0;
      v = to_be64(v);
      content_buf.writeBytes(&v, sizeof(v));
      payload_length = 8;
    } else if (std::holds_alternative<TextString>(value)) {
      const auto &v = std::get<TextString>(value).value;
      content_buf.writePadded(v.data(), v.size());
      payload_length = v.size();
    } else if (std::holds_alternative<ByteString>(value)) {
      const auto &v = std::get<ByteString>(value).value;
      content_buf.writePadded(v.data(), v.size());
      payload_length = v.size();
    } else if (std::holds_alternative<DateTime>(value)) {
      int64_t v = std::get<DateTime>(value).value;
      v = to_be64(v);
      content_buf.writeBytes(&v, sizeof(v));
      payload_length = 8;
    } else if (std::holds_alternative<Interval>(value)) {
      uint32_t v = std::get<Interval>(value).value;
      v = to_be32(v);
      content_buf.writeBytes(&v, sizeof(v));
      payload_length = 4;
    }

    // Write Length (4 bytes, big-endian)
    buf.writeByte((payload_length >> 24) & 0xFF);
    buf.writeByte((payload_length >> 16) & 0xFF);
    buf.writeByte((payload_length >> 8) & 0xFF);
    buf.writeByte(payload_length & 0xFF);

    // Write content (already padded from content_buf)
    if (content_buf.size() > 0) {
      buf.writeBytes(content_buf.data(), content_buf.size());
    }

    // Add padding to align to 8 bytes
    size_t total_so_far = 3 + 1 + 4 + content_buf.size();  // tag + type + length + content
    size_t padding = (8 - (total_so_far % 8)) % 8;
    for (size_t i = 0; i < padding; ++i) {
      buf.writeByte(0);
    }
  }

  std::shared_ptr<Element>
      Element::deserialize(std::span<const uint8_t> data, size_t &offset) {
    if (offset + 8 > data.size()) {
      throw KmipException("Buffer too short for header");
    }

    // Read Tag (3 bytes)
    uint32_t tag =
        (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];

    // Read Type (1 byte)
    Type type = static_cast<Type>(data[offset + 3]);

    // Read Length (4 bytes)
    uint32_t length = (data[offset + 4] << 24) | (data[offset + 5] << 16) |
                      (data[offset + 6] << 8) | data[offset + 7];

    offset += 8;

    // Check bounds
    // For Structure, length is the length of contents.
    // For Primitives, length is the unpadded length.
    // We need to calculate padded length to skip correctly.
    size_t padded_length = length;
    if (length % 8 != 0 && type != ::KMIP_TYPE_STRUCTURE) {
      padded_length +=
          (8 -
           (length % 8));  // Doesn't apply to structure?
                           // Structure variable length is usually handled
                           // differently because it contains other items
                           // aligned on 8-byte boundaries. Actually for
                           // Structure type, length is sum of encoded items.
      // Since all encoded items are multiple of 8 bytes, Structure length
      // should be multiple of 8.
    }

    if (type == ::KMIP_TYPE_STRUCTURE) {
      // Recursive parse
      auto struct_elem = std::make_shared<Element>();
      struct_elem->tag = static_cast<Tag>(tag);
      struct_elem->type = type;
      struct_elem->value = Structure{};

      size_t current_struct_offset = 0;
      while (current_struct_offset < length) {
        size_t item_offset = offset;
        auto child = deserialize(data, item_offset);
        std::get<Structure>(struct_elem->value).add(child);
        size_t consumed = item_offset - offset;
        current_struct_offset += consumed;
        offset = item_offset;
      }
      return struct_elem;
    } else {
      if (offset + padded_length > data.size()) {
        throw KmipException("Buffer too short for value");
      }

      auto elem = std::make_shared<Element>();
      elem->tag = static_cast<Tag>(tag);
      elem->type = type;

      switch (type) {
        case ::KMIP_TYPE_INTEGER: {
          if (length != 4) {
            throw KmipException("Invalid length for Integer");
          }
          int32_t val;
          uint32_t raw = (data[offset] << 24) | (data[offset + 1] << 16) |
                         (data[offset + 2] << 8) | data[offset + 3];
          // raw is equivalent to big-endian read
          // we can just use memcpy if valid but manual reconstruction is safer
          // for endianness Actually raw is correct for big endian 4 bytes
          std::memcpy(&val, &raw, 4);  // Interpreting uint32 as int32
          elem->value = Integer{val};
          break;
        }
        case ::KMIP_TYPE_LONG_INTEGER: {
          if (length != 8) {
            throw KmipException("Invalid length for Long Integer");
          }
          uint64_t raw = ((uint64_t) data[offset] << 56) |
                         ((uint64_t) data[offset + 1] << 48) |
                         ((uint64_t) data[offset + 2] << 40) |
                         ((uint64_t) data[offset + 3] << 32) |
                         ((uint64_t) data[offset + 4] << 24) |
                         ((uint64_t) data[offset + 5] << 16) |
                         ((uint64_t) data[offset + 6] << 8) |
                         (uint64_t) data[offset + 7];
          int64_t val;
          std::memcpy(&val, &raw, 8);
          elem->value = LongInteger{val};
          break;
        }
        case ::KMIP_TYPE_BOOLEAN: {
          if (length != 8) {
            throw KmipException("Invalid length for Boolean");
          }
          uint64_t raw = ((uint64_t) data[offset] << 56) |
                         ((uint64_t) data[offset + 1] << 48) |
                         ((uint64_t) data[offset + 2] << 40) |
                         ((uint64_t) data[offset + 3] << 32) |
                         ((uint64_t) data[offset + 4] << 24) |
                         ((uint64_t) data[offset + 5] << 16) |
                         ((uint64_t) data[offset + 6] << 8) |
                         (uint64_t) data[offset + 7];
          elem->value = Boolean{raw != 0};
          break;
        }
        case ::KMIP_TYPE_ENUMERATION: {
          if (length != 4) {
            throw KmipException("Invalid length for Enumeration");
          }
          uint32_t raw = (data[offset] << 24) | (data[offset + 1] << 16) |
                         (data[offset + 2] << 8) | data[offset + 3];
          elem->value = Enumeration{(int32_t) raw};
          break;
        }
        case ::KMIP_TYPE_TEXT_STRING: {
          std::string s(reinterpret_cast<const char *>(&data[offset]), length);
          elem->value = TextString{s};
          break;
        }
        case ::KMIP_TYPE_BYTE_STRING: {
          std::vector<uint8_t> v(
              data.begin() + offset, data.begin() + offset + length
          );
          elem->value = ByteString{v};
          break;
        }
        case ::KMIP_TYPE_DATE_TIME: {
          if (length != 8) {
            throw KmipException("Invalid length for DateTime");
          }
          uint64_t raw = ((uint64_t) data[offset] << 56) |
                         ((uint64_t) data[offset + 1] << 48) |
                         ((uint64_t) data[offset + 2] << 40) |
                         ((uint64_t) data[offset + 3] << 32) |
                         ((uint64_t) data[offset + 4] << 24) |
                         ((uint64_t) data[offset + 5] << 16) |
                         ((uint64_t) data[offset + 6] << 8) |
                         (uint64_t) data[offset + 7];
          int64_t val;
          std::memcpy(&val, &raw, 8);
          elem->value = DateTime{val};
          break;
        }
        case ::KMIP_TYPE_INTERVAL: {
          if (length != 4) {
            throw KmipException("Invalid length for Interval");
          }
          uint32_t raw = (data[offset] << 24) | (data[offset + 1] << 16) |
                         (data[offset + 2] << 8) | data[offset + 3];
          elem->value = Interval{raw};
          break;
        }
        case ::KMIP_TYPE_BIG_INTEGER: {
          std::vector<uint8_t> v(
              data.begin() + offset, data.begin() + offset + length
          );
          elem->value = BigInteger{v};
          break;
        }
        default:
          throw KmipException("Unknown type " + std::to_string(type));
      }

      offset += padded_length;
      return elem;
    }
  }

  // Factory methods
  std::shared_ptr<Element> Element::createStructure(Tag t) {
    return std::make_shared<Element>(t, ::KMIP_TYPE_STRUCTURE, Structure{});
  }
  std::shared_ptr<Element> Element::createInteger(Tag t, int32_t v) {
    return std::make_shared<Element>(t, ::KMIP_TYPE_INTEGER, Integer{v});
  }
  std::shared_ptr<Element> Element::createLongInteger(Tag t, int64_t v) {
    return std::make_shared<Element>(
        t, ::KMIP_TYPE_LONG_INTEGER, LongInteger{v}
    );
  }
  std::shared_ptr<Element> Element::createBoolean(Tag t, bool v) {
    return std::make_shared<Element>(t, ::KMIP_TYPE_BOOLEAN, Boolean{v});
  }
  std::shared_ptr<Element> Element::createEnumeration(Tag t, int32_t v) {
    return std::make_shared<Element>(
        t, ::KMIP_TYPE_ENUMERATION, Enumeration{v}
    );
  }
  std::shared_ptr<Element>
      Element::createTextString(Tag t, const std::string &v) {
    return std::make_shared<Element>(t, ::KMIP_TYPE_TEXT_STRING, TextString{v});
  }
  std::shared_ptr<Element>
      Element::createByteString(Tag t, const std::vector<uint8_t> &v) {
    return std::make_shared<Element>(t, ::KMIP_TYPE_BYTE_STRING, ByteString{v});
  }
  std::shared_ptr<Element> Element::createDateTime(Tag t, int64_t v) {
    return std::make_shared<Element>(t, ::KMIP_TYPE_DATE_TIME, DateTime{v});
  }
  std::shared_ptr<Element> Element::createInterval(Tag t, uint32_t v) {
    return std::make_shared<Element>(t, ::KMIP_TYPE_INTERVAL, Interval{v});
  }
  std::shared_ptr<Element>
      Element::createBigInteger(Tag t, const std::vector<uint8_t> &v) {
    return std::make_shared<Element>(t, ::KMIP_TYPE_BIG_INTEGER, BigInteger{v});
  }

  // Helper accessors
  Structure *Element::asStructure() {
    return std::get_if<Structure>(&value);
  }
  const Structure *Element::asStructure() const {
    return std::get_if<Structure>(&value);
  }

  std::shared_ptr<Element> Structure::find(Tag tag) const {
    for (const auto &item : items) {
      if (item->tag == tag) {
        return item;
      }
    }
    return nullptr;
  }

  std::vector<std::shared_ptr<Element>> Structure::findAll(Tag tag) const {
    std::vector<std::shared_ptr<Element>> matches;
    for (const auto &item : items) {
      if (item->tag == tag) {
        matches.push_back(item);
      }
    }
    return matches;
  }

  std::shared_ptr<Element> Element::getChild(Tag tag) const {
    const auto *s = std::get_if<Structure>(&value);
    if (!s) {
      return nullptr;
    }
    return s->find(tag);
  }

  std::vector<std::shared_ptr<Element>> Element::getChildren(Tag tag) const {
    const auto *s = std::get_if<Structure>(&value);
    if (!s) {
      return {};
    }
    return s->findAll(tag);
  }

  int32_t Element::toInt() const {
    if (auto *v = std::get_if<Integer>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not Integer");
  }

  int64_t Element::toLong() const {
    if (auto *v = std::get_if<LongInteger>(&value)) {
      return v->value;
    }
    if (auto *v = std::get_if<DateTime>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not Long/DateTime");
  }

  bool Element::toBool() const {
    if (auto *v = std::get_if<Boolean>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not Boolean");
  }

  std::string Element::toString() const {
    if (auto *v = std::get_if<TextString>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not TextString");
  }

  std::vector<uint8_t> Element::toBytes() const {
    if (auto *v = std::get_if<ByteString>(&value)) {
      return v->value;
    }
    if (auto *v = std::get_if<BigInteger>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not ByteString/BigInteger");
  }

  int32_t Element::toEnum() const {
    if (auto *v = std::get_if<Enumeration>(&value)) {
      return v->value;
    }
    throw KmipException("Element is not Enumeration");
  }

}  // namespace kmipcore
