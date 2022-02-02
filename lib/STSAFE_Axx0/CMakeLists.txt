add_library(core-modules OBJECT "")


target_sources(
        core-modules
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/CoreModules/Src/stsafea_core.c
        ${CMAKE_CURRENT_LIST_DIR}/CoreModules/Src/stsafea_crypto.c
        ${CMAKE_CURRENT_LIST_DIR}/CoreModules/Src/stsafea_service.c
)

target_include_directories(
        core-modules
        PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/CoreModules/Inc
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
)

target_compile_options(
        core-modules
        PUBLIC
        -DSTSAFE_A110
)