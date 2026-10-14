# Vendors this repository the way Percona Server does (add_subdirectory),
# for ci/check-install.sh to check that its install installs nothing.
cmake_minimum_required(VERSION 3.14)
project(kmipclient_vendor_test CXX)

add_subdirectory(${KMIPCLIENT_SOURCE_DIR} kmipclient)
