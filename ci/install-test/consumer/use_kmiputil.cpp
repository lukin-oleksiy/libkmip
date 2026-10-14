#include "kmipclient/kmipclient_version.hpp"
#include "kmiputil/KeyGenerator.hpp"
#include "kmiputil/kmiputil_version.hpp"

#include <iostream>

int main() {
  const auto key = kmiputil::KeyGenerator::generate_aes();
  std::cout << "kmipclient " << KMIPCLIENT_VERSION_STR << ", kmiputil "
            << KMIPUTIL_VERSION_STR << ", AES key of " << key.value().size()
            << " bytes\n";
  return key.value().size() == 32 ? 0 : 1;
}
