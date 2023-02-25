add_executable(stsafe_engine_test_suit)

target_sources(
        stsafe_engine_test_suit
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/ecdh_test.c
        ${CMAKE_CURRENT_LIST_DIR}/ecdsa_sign_verify.c
        ${CMAKE_CURRENT_LIST_DIR}/pkey_test.c
        ${CMAKE_CURRENT_LIST_DIR}/query_test.c
        ${CMAKE_CURRENT_LIST_DIR}/rand_test.c
        ${CMAKE_CURRENT_LIST_DIR}/test_stsafe_engine.c
)

target_link_libraries(
        stsafe_engine_test_suit
        Stsafe
        OpenSSL::SSL
        OpenSSL::Crypto
)
