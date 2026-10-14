# Builds against an installed kmipclient package (see ci/check-install.sh).
# Sets no C++ standard of its own: the kmipclient:: targets must bring C++20.
cmake_minimum_required(VERSION 3.14)
project(kmipclient_install_test CXX)

find_package(kmipclient REQUIRED)

# kmiputil pulls in kmipclient and kmipcore.
add_executable(use_kmiputil use_kmiputil.cpp)
target_link_libraries(use_kmiputil PRIVATE kmipclient::kmiputil)

# kmipcore on its own, as a protocol-only consumer would link it.
add_executable(use_kmipcore use_kmipcore.cpp)
target_link_libraries(use_kmipcore PRIVATE kmipclient::kmipcore)
