add_executable(stsafe_genkey)

target_sources(
        stsafe_genkey
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/stsafe_genkey.c
)

target_link_libraries(
        stsafe_genkey
        Stsafe
        OpenSSL::SSL
        OpenSSL::Crypto
)
