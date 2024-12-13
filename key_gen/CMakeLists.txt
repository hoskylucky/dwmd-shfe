add_executable(key_gen main.cpp)
target_link_libraries(key_gen 
    PRIVATE fmt::fmt-header-only
    PRIVATE lcxx::lcxx
    PRIVATE lcxx::identifiers
)