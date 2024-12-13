cmake_minimum_required (VERSION 3.0.0)
project(jxkr_mdapi)

aux_source_directory(. JXKR_MD_SRC)

add_library(jxkr_mdapi SHARED ${JXKR_MD_SRC})
target_link_libraries(jxkr_mdapi PUBLIC ${CCBASE_A})

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fPIC")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fPIC")
add_library(jxkr_mdapi_static STATIC ${JXKR_MD_SRC} ${CCBASE})
