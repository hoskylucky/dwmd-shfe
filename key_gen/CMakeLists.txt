add_executable(key_gen main.cpp)
target_link_libraries(key_gen 
    PRIVATE fmt::fmt-header-only
    PRIVATE lcxx::lcxx
    PRIVATE lcxx::identifiers
)

add_custom_command(
    TARGET key_gen POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E env ${CMAKE_SOURCE_DIR}/package.sh jxkr.shfe.demo.v${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running package.sh with version ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}"
)