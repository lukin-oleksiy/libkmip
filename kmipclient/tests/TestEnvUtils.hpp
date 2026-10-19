/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_TESTS_TEST_ENV_UTILS_HPP
#define KMIPCLIENT_TESTS_TEST_ENV_UTILS_HPP

#include <algorithm>
#include <cstdlib>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace kmipclient::test {

  inline bool is_env_flag_enabled(const char *name) {
    const char *value = std::getenv(name);
    return value != nullptr && std::string_view(value) == "1";
  }

  // Expects `found` to hold exactly the ids in `created`: none missing, none
  // extra and none repeated.
  inline void expect_exactly_ids(
      std::vector<std::string> found, std::vector<std::string> created
  ) {
    std::sort(found.begin(), found.end());
    std::sort(created.begin(), created.end());
    EXPECT_EQ(found.size(), created.size())
        << "located " << found.size() << " ids, created " << created.size();
    EXPECT_TRUE(found == created) << "located ids differ from created ids";
  }

}  // namespace kmipclient::test

#endif  // KMIPCLIENT_TESTS_TEST_ENV_UTILS_HPP
