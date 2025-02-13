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

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

# -- Get the OpenSSL's engine directory
if(OPENSSL_FOUND AND PKG_CONFIG_FOUND)
    pkg_get_variable(OPENSSL_ENGINE_DIR libcrypto enginesdir)
endif()

message(STATUS "OpenSSL Engine: " ${OPENSSL_ENGINE_DIR} )

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
if (NOT (${CMAKE_INSTALL_PREFIX} STREQUAL "/usr" ) )
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
endif()

# generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BUILD_SHARED_LIBS ON)

# compile options
set(DEBUG_LEVEL "4" CACHE STRING "Stsafe: library debug level"    FORCE)
set_property(CACHE DEBUG_LEVEL PROPERTY STRINGS 1 2 3 4 )

#set(STSAFEA_DEVICE_ADDRESS  "0x0020"  CACHE STRING "Stsafe: i2c address"    FORCE)
set(STSAFEA_DEFAULT_I2CBUS  "1"     CACHE STRING "Stsafe: i2c bus"    FORCE)
set(STSAFE_ECDSA_VERIFY     1      CACHE BOOL "Stsafe: ECDSA verify"    FORCE)
set(STSAFE_ECDH_ENABLE      1      CACHE BOOL "Stsafe: ECDH enable"    FORCE)

set(PACKAGE_VERSION "2.0.5")

message(STATUS "Stsafe: debug level: " ${DEBUG_LEVEL})
message(STATUS "Stsafe: device address: " ${STSAFEA_DEVICE_ADDRESS})
message(STATUS "Stsafe: i2c bus: " ${STSAFEA_DEFAULT_I2CBUS})
message(STATUS "Stsafe: verify ECDSA: " ${STSAFE_ECDSA_VERIFY})
message(STATUS "Stsafe: enable ECDH: " ${STSAFE_ECDH_ENABLE})

configure_file(${CMAKE_CURRENT_LIST_DIR}/config.h.in "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

# Include core-modules
include(lib/STSAFE_Axx0/CMakeLists.txt)

add_library(Stsafe "")
set_target_properties(Stsafe PROPERTIES PREFIX "")

target_sources(
        Stsafe
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/engine_init.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_cipher.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_cmd.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_configuration.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_ecdsa.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_init.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_pem_priv.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_pkey_meth.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_rand.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_zone.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafea_crypto_openssl_interface_engine.c
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafea_service_interface_engine.c
        $<TARGET_OBJECTS:core-modules>
)

target_include_directories(
        Stsafe
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/inc>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/lib/STSAFE_Axx0/CoreModules/Inc>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>
)

target_compile_options(
    Stsafe
        PUBLIC
        -DSTSAFE_A110
        -DBUS_CONF_DEBUG
        -DDEBUG_LEVEL=${DEBUG_LEVEL}
        -DSTSAFEA_DEFAULT_I2CBUS=\"${STSAFEA_DEFAULT_I2CBUS}\"
#        -DSTSAFEA_DEVICE_ADDRESS=${STSAFEA_DEVICE_ADDRESS}
        -DSTSAFE_ECDSA_VERIFY=${STSAFE_ECDSA_VERIFY}
        -DSTSAFE_ECDH_ENABLE=${STSAFE_ECDH_ENABLE}
)

# Include examples
add_subdirectory(Examples)
