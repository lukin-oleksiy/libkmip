cmake_minimum_required(VERSION 3.14)

project(kmip CXX)

enable_testing()

option(WITH_ASAN "Enable AddressSanitizer for project build" OFF)

if(WITH_ASAN)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    set(_asan_compile_flags "-fsanitize=address -fno-omit-frame-pointer")
    set(_asan_link_flags "-fsanitize=address")

    string(APPEND CMAKE_CXX_FLAGS " ${_asan_compile_flags}")
    string(APPEND CMAKE_EXE_LINKER_FLAGS " ${_asan_link_flags}")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " ${_asan_link_flags}")
  else()
    message(FATAL_ERROR "WITH_ASAN=ON is supported only with Clang or GCC compilers")
  endif()
endif()

# Install rules (the libraries, their headers and the find_package(kmipclient)
# package) are on by default only when this repository is the top-level
# project. Percona Server vendors it with add_subdirectory() and links the
# static libraries into its own binaries; installing them there would only
# leave unpackaged files in its RPM/DEB builds. A vendoring project can still
# opt in by setting KMIPCLIENT_INSTALL=ON.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(_kmipclient_is_top_level ON)
else()
  set(_kmipclient_is_top_level OFF)
endif()
option(KMIPCLIENT_INSTALL
  "Generate install rules for kmipcore, kmipclient, kmiputil and the kmipclient CMake package"
  ${_kmipclient_is_top_level}
)

add_subdirectory(kmipcore)
add_subdirectory(kmipclient)
add_subdirectory(kmiputil)

if(KMIPCLIENT_INSTALL)
  # Lets a downstream project consume an installed build with
  # find_package(kmipclient), instead of just vendoring this repo with
  # add_subdirectory(). kmipcore, kmipclient and kmiputil version independently
  # (see their own *_version.hpp), but the installed package as a whole is
  # versioned by kmipclient, the one EXPORT set they're all part of.
  include(CMakePackageConfigHelpers)
  include(GNUInstallDirs)

  set(KMIP_INSTALL_CMAKEDIR
      "${CMAKE_INSTALL_LIBDIR}/cmake/kmipclient"
      CACHE STRING "Installation directory for the kmipclient CMake package config files"
  )

  install(
    EXPORT kmipclient
    NAMESPACE kmipclient::
    FILE kmipclientTargets.cmake
    DESTINATION ${KMIP_INSTALL_CMAKEDIR}
  )

  configure_package_config_file(
    cmake/kmipclientConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/kmipclientConfig.cmake
    INSTALL_DESTINATION ${KMIP_INSTALL_CMAKEDIR}
  )

  # The package version is read from kmipclient_version.hpp, so the two can't
  # drift apart.
  file(
    STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/kmipclient/include/kmipclient/kmipclient_version.hpp
    _kmipclient_version_defines
    REGEX "^#define KMIPCLIENT_VERSION_(MAJOR|MINOR|PATCH) +[0-9]+"
  )
  foreach(_part MAJOR MINOR PATCH)
    string(REGEX MATCH "KMIPCLIENT_VERSION_${_part} +([0-9]+)" _match "${_kmipclient_version_defines}")
    if(NOT _match)
      message(FATAL_ERROR "KMIPCLIENT_VERSION_${_part} not found in kmipclient_version.hpp")
    endif()
    set(_kmipclient_version_${_part} ${CMAKE_MATCH_1})
  endforeach()

  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/kmipclientConfigVersion.cmake
    VERSION ${_kmipclient_version_MAJOR}.${_kmipclient_version_MINOR}.${_kmipclient_version_PATCH}
    COMPATIBILITY SameMinorVersion
  )

  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/kmipclientConfig.cmake
          ${CMAKE_CURRENT_BINARY_DIR}/kmipclientConfigVersion.cmake
    DESTINATION ${KMIP_INSTALL_CMAKEDIR}
  )
endif()

find_package(Doxygen)

option(BUILD_DOCS "Build API documentation with Doxygen" ${DOXYGEN_FOUND})

if(BUILD_DOCS)
  if(NOT DOXYGEN_FOUND)
    message(FATAL_ERROR "BUILD_DOCS is ON but Doxygen was not found.")
  endif()

  configure_file(Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile COPYONLY)

  add_custom_target(doc
    COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Generating API documentation with Doxygen"
    VERBATIM
  )

  # Make the 'doc' target depend on your build targets if necessary
  # add_dependencies(doc your_library your_executable)
else()
  message(STATUS "Doxygen not found or BUILD_DOCS=OFF, skipping documentation generation.")
endif()
