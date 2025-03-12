#pragma once

#include "kmipcore/kmip_enums.hpp"

#include <cstdint>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace kmipcore {

  /** @brief Raw key bytes container type. */
  using key_t = std::vector<unsigned char>;
  /** @brief Generic binary payload container type. */
  using bin_data_t = std::vector<unsigned char>;
  /** @brief KMIP unique identifier textual type. */
  using id_t = std::string;
  /** @brief Collection of KMIP unique identifiers. */
  using ids_t = std::vector<std::string>;
  /** @brief KMIP Name attribute textual type. */
  using name_t = std::string;
  /** @brief Collection of textual names. */
  using names_t = std::vector<std::string>;
  /** @brief Secret payload bytes container type. */
  using secret_t = std::vector<unsigned char>;
  /** @brief Generic string attribute map type. */
  using attributes_t = std::unordered_map<std::string, std::string>;

  /** Convert a KMIP state enum value to a human-readable string. */
  inline const char *state_to_string(int32_t value) {
    switch (static_cast<enum state>(value)) {
      case KMIP_STATE_PRE_ACTIVE:
        return "KMIP_STATE_PRE_ACTIVE";
      case KMIP_STATE_ACTIVE:
        return "KMIP_STATE_ACTIVE";
      case KMIP_STATE_DEACTIVATED:
        return "KMIP_STATE_DEACTIVATED";
      case KMIP_STATE_COMPROMISED:
        return "KMIP_STATE_COMPROMISED";
      case KMIP_STATE_DESTROYED:
        return "KMIP_STATE_DESTROYED";
      case KMIP_STATE_DESTROYED_COMPROMISED:
        return "KMIP_STATE_DESTROYED_COMPROMISED";
      default:
        return "UNKNOWN_KMIP_STATE";
    }
  }

  /** @brief Stream formatter for KMIP lifecycle state values. */
  inline std::ostream &operator<<(std::ostream &out, const state value) {
    return out << state_to_string(static_cast<int32_t>(value));
  }

}  // namespace kmipcore

