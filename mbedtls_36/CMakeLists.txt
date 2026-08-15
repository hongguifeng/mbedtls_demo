cmake_minimum_required(VERSION 3.14)
project(mbedtls_36_demo C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Download mbedTLS 3.6.0 LTS
include(FetchContent)
FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.0
)

# Disable mbedTLS tests/programs to speed up build
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(mbedtls)

# Common include for all examples
include_directories(${mbedtls_SOURCE_DIR}/include)

# Helper function to add example targets
function(add_example name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name}
        mbedtls
        mbedx509
        mbedcrypto
    )
endfunction()

# Examples - ordered from basic to advanced
add_example(01_hash         01_hash/main.c)
add_example(02_aes          02_aes/main.c)
add_example(03_rsa          03_rsa/main.c)
add_example(04_ecc          04_ecc/main.c)
add_example(05_x509_parse   05_x509_parse/main.c)
target_compile_definitions(05_x509_parse
    PRIVATE MBEDTLS_TEST_DATA_DIR="${mbedtls_SOURCE_DIR}/tests/data_files")
add_example(06_tls_client   06_tls_client/main.c)
add_example(07_tls_mutual   07_tls_mutual/main.c)
target_link_libraries(07_tls_mutual pthread)

add_example(08_custom_bio   08_custom_bio/main.c)
target_link_libraries(08_custom_bio pthread)
