#pragma once

#include "kmipcore/key.hpp"
#include "kmipcore/kmip_attribute_names.hpp"
#include "kmipcore/secret.hpp"
#include "kmipcore/types.hpp"

namespace kmipclient {

  /** @brief Alias for KMIP attribute map type. */
  using kmipcore::attributes_t;
  /** @brief Alias for binary data buffer type. */
  using kmipcore::bin_data_t;
  /** @brief Alias for KMIP unique identifier type. */
  using kmipcore::id_t;
  /** @brief Alias for a list of KMIP unique identifiers. */
  using kmipcore::ids_t;
  /** @brief Alias for raw key bytes container type. */
  using kmipcore::key_t;
  /** @brief Alias for supported key-kind discriminator enum. */
  using kmipcore::KeyType;
  /** @brief Alias for KMIP textual name type. */
  using kmipcore::name_t;
  /** @brief Alias for a list of textual names. */
  using kmipcore::names_t;
  /** @brief Alias for KMIP secret object representation. */
  using kmipcore::Secret;
  /** @brief Alias for secret binary payload container. */
  using kmipcore::secret_t;

  /** @brief Canonical KMIP attribute name for object name. */
  inline const std::string &KMIP_ATTR_NAME_NAME = kmipcore::KMIP_ATTR_NAME_NAME;
  /** @brief Canonical KMIP attribute name for object group. */
  inline const std::string &KMIP_ATTR_NAME_GROUP =
      kmipcore::KMIP_ATTR_NAME_GROUP;
  /** @brief Canonical KMIP attribute name for object state. */
  inline const std::string &KMIP_ATTR_NAME_STATE =
      kmipcore::KMIP_ATTR_NAME_STATE;
  /** @brief Canonical KMIP attribute name for unique identifier. */
  inline const std::string &KMIP_ATTR_NAME_UNIQUE_IDENTIFIER =
      kmipcore::KMIP_ATTR_NAME_UNIQUE_IDENTIFIER;

  /** @brief Re-export stream formatter overloads from kmipcore. */
  using kmipcore::operator<<;

}  // namespace kmipclient
