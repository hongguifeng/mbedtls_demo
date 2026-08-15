cmake_minimum_required(VERSION 3.14)
project(mbedtls_demo C)

# This is a top-level dispatcher. Each sub-project has its own CMakeLists.txt:
#   mbedtls_36/ - mbedTLS 3.6.0 LTS (legacy API examples)
#   mbedtls_42/ - mbedTLS 4.2.0 (PSA Crypto API examples)
#
# Build each independently:
#   cd mbedtls_36 && mkdir build && cd build && cmake .. && make
#   cd mbedtls_42 && mkdir build && cd build && cmake .. && make

message(STATUS "mbedtls_demo top-level project")
message(STATUS "  Sub-projects:")
message(STATUS "    mbedtls_36/ - mbedTLS 3.6.0 LTS (examples 01-08)")
message(STATUS "    mbedtls_42/ - mbedTLS 4.2.0 PSA Crypto API (examples 09-15)")
message(STATUS "")
message(STATUS "Build each sub-project independently:")
message(STATUS "  cd mbedtls_36 && mkdir -p build && cd build && cmake .. && make")
message(STATUS "  cd mbedtls_42 && mkdir -p build && cd build && cmake .. && make")
