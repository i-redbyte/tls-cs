cmake_minimum_required(VERSION 3.13)
project(tls_cs)
set(CMAKE_C_STANDARD 11)

set(OPENSSL_ROOT_DIR /usr/local/opt/openssl@3)
find_package(OpenSSL 3.0.2 REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(tls_server "server.c")
target_link_libraries(tls_server ${OPENSSL_LIBRARIES})
add_executable(tls_client "client.c")
target_link_libraries(tls_client ${OPENSSL_LIBRARIES})

install(TARGETS tls_server RUNTIME DESTINATION bin)
install(TARGETS tls_client RUNTIME DESTINATION bin)

## Check OpenSSL
include(FindOpenSSL)
message(STATUS "OPENSSL_FOUND = ${OPENSSL_FOUND}")
message(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OPENSSL_CRYPTO_LIBRARY = ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "OPENSSL_CRYPTO_LIBRARIES = ${OPENSSL_CRYPTO_LIBRARIES}")
message(STATUS "OPENSSL_SSL_LIBRARY = ${OPENSSL_SSL_LIBRARY}")
message(STATUS "OPENSSL_SSL_LIBRARIES = ${OPENSSL_SSL_LIBRARIES}")
message(STATUS "OPENSSL_LIBRARIES = ${OPENSSL_LIBRARIES}")
message(STATUS "OPENSSL_VERSION = ${OPENSSL_VERSION}")
message(STATUS "OPENSSL_APPLINK_SOURCE = ${OPENSSL_APPLINK_SOURCE}")
