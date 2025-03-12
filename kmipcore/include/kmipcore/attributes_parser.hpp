#pragma once

#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/types.hpp"

#include <memory>
#include <vector>

namespace kmipcore {

  /**
   * @brief Utilities for decoding KMIP Attribute structures into a string map.
   */
  class AttributesParser {
  public:
    /** @brief Default constructor. */
    AttributesParser() = default;
    /**
     * @brief Parses KMIP attribute elements into name/value pairs.
     * @param attributes Raw KMIP attribute elements.
     * @return Parsed attribute map keyed by attribute name.
     */
    static attributes_t
        parse(const std::vector<std::shared_ptr<Element>> &attributes);
  };

}  // namespace kmipcore
