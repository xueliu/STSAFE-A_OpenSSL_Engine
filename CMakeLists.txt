# -- Minimum required version
cmake_minimum_required (VERSION 3.11.0)

# -- Project name
project (stsafe)

# -- Various includes
include (GenerateExportHeader)
include (CMakePackageConfigHelpers)
include (GNUInstallDirs)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")

# -- Required to build
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# -- Set cxx 11 standard default to achieve the compatibility with mtios
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
if (NOT (${CMAKE_INSTALL_PREFIX} STREQUAL "/usr" ) )
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BUILD_SHARED_LIBS ON)


# Include core-modules
include(lib/STSAFE_Axx0/CMakeLists.txt)

add_library(stsafe "")

target_sources(
        stsafe
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/engine_init.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_cipher.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_cmd.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_configuration.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_ecdsa.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_init.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_pkey_meth.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_rand.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_zone.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafea_crypto_openssl_interface_engine.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafea_service_interface_engine.c
        $<TARGET_OBJECTS:core-modules>
)

target_include_directories(
        stsafe
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/inc>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/lib/STSAFE_Axx0/CoreModules/Inc>
)

target_compile_options(
        stsafe
        PUBLIC
        -DSTSAFE_A110
        -DBUS_CONF_DEBUG
)

# Include examples
add_subdirectory(Examples)
