cmake_minimum_required(VERSION 3.14)
project(mbedtls_42_demo C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Download mbedTLS 4.2.0 (with tf-psa-crypto and framework submodules)
include(FetchContent)
FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v4.2.0
    GIT_SUBMODULES "tf-psa-crypto" "framework"
)

# Disable mbedTLS tests/programs to speed up build
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(mbedtls)

# PSA examples only need tfpsacrypto (the crypto library extracted in 4.x)
# tfpsacrypto PUBLIC include dirs: tf-psa-crypto/include/ (has psa/ and mbedtls/)
function(add_psa_example name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} tfpsacrypto)
endfunction()

# PSA Crypto API examples
add_psa_example(09_psa_hash         09_psa_hash/main.c)
add_psa_example(10_psa_cipher       10_psa_cipher/main.c)
add_psa_example(11_psa_aead         11_psa_aead/main.c)
add_psa_example(12_psa_mac          12_psa_mac/main.c)
add_psa_example(13_psa_asymmetric   13_psa_asymmetric/main.c)
add_psa_example(14_psa_kdf          14_psa_kdf/main.c)
add_psa_example(15_psa_key_mgmt     15_psa_key_mgmt/main.c)
