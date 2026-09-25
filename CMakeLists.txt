cmake_minimum_required(VERSION 3.20.0)

# nn-modules location: env (standalone build via nn-app-build) or the monorepo
# sibling (../../modules) as the fallback so in-tree builds keep working.
set(NN_MODULES_DIR "$ENV{NN_MODULES_DIR}")
if(NOT NN_MODULES_DIR)
    set(NN_MODULES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../modules)
endif()

include(${NN_MODULES_DIR}/cmake/nn_version.cmake)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(mdns_ot_esp32c6)

add_subdirectory(${NN_MODULES_DIR}/libs/node_mgr node_mgr_build)

target_sources(app PRIVATE
    src/main.c
    src/mbedtls_threading_zephyr.c
)

target_include_directories(app PRIVATE include)
