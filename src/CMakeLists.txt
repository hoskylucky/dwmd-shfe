aux_source_directory(. JXKR_MD_SRC)

add_library(jxkr_shfeapi_impl STATIC ${JXKR_MD_SRC})

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fPIC")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")

target_link_libraries(jxkr_shfeapi_impl
        PRIVATE fmt::fmt-header-only
        PRIVATE spdlog::spdlog_header_only
        PRIVATE nlohmann_json::nlohmann_json
        PRIVATE lcxx::lcxx
        PRIVATE lcxx::identifiers
)

add_library(jxkr_shfeapi STATIC
        $<TARGET_OBJECTS:jxkr_shfeapi_impl>
        $<TARGET_OBJECTS:lcxx::lcxx> 
        $<TARGET_OBJECTS:lcxx::crypto> 
        $<TARGET_OBJECTS:lcxx::ident_utils> 
        $<TARGET_OBJECTS:lcxx::identifiers>
)