#pragma once

#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/types.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace kmipcore {

  /**
   * @brief Minimal KMIP Secret Data model.
   */
  class Secret {
  public:
    /** Raw secret payload bytes. */
    secret_t value;
    /** Lifecycle state of this secret object. */
    enum state state = KMIP_STATE_PRE_ACTIVE;
    /** KMIP secret data type discriminator. */
    enum secret_data_type secret_type = PASSWORD;

    /** @brief Constructs an empty secret. */
    Secret() = default;
    /** @brief Constructs a secret from payload and metadata. */
    Secret(secret_t val, enum state st, enum secret_data_type type)
      : value(std::move(val)), state(st), secret_type(type) {}

    /** @brief Returns all attached secret attributes. */
    [[nodiscard]] const attributes_t &attributes() const noexcept {
      return secret_attributes;
    }

    /**
     * @brief Returns value of a required secret attribute.
     * @throws std::out_of_range if the attribute is missing.
     */
    [[nodiscard]] const std::string &
        attribute_value(const std::string &name) const {
      return secret_attributes.at(name);
    }

    /** @brief Sets or replaces one secret attribute value. */
    void set_attribute(
        const std::string &name, const std::string &val
    ) noexcept {
      secret_attributes[name] = val;
    }

    /**
     * @brief Creates a Secret from text bytes.
     * @param text Source text payload.
     * @param type KMIP secret data type.
     * @param st Initial lifecycle state.
     */
    [[nodiscard]] static Secret from_text(
        std::string_view text,
        enum secret_data_type type = PASSWORD,
        enum state st = KMIP_STATE_PRE_ACTIVE
    ) {
      return Secret{
          secret_t(text.begin(), text.end()), st, type};
    }

    /** @brief Returns payload interpreted as UTF-8/byte-preserving text. */
    [[nodiscard]] std::string as_text() const {
      return std::string(value.begin(), value.end());
    }

  private:
    attributes_t secret_attributes;
  };

}  // namespace kmipcore

