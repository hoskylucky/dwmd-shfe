cmake_minimum_required (VERSION 3.0.0)

project(jxkr)

if (MSVC)
    # warning level 4 and all warnings as errors
    add_compile_options(/W4 /WX)
else()
    # lots of warnings and all warnings as errors
    add_compile_options(-Wextra -Werror -Wno-unused-function -Wno-unused-variable -Wno-sign-compare -Wno-unused-parameter)
endif()

add_definitions(-D_GNU_SOURCE -D_XOPEN_SOURCE)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=gnu99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

if(CYGWIN)
  SET(CMAKE_EXE_LINKER_FLAGS "-Wl,-lrt -lm -lpthread -ldl -liconv" )
else()
  SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--hash-style=sysv -lrt -lm -lpthread -ldl" )
endif()

#cmake -B build -DCMAKE_BUILD_TYPE=Debug
#set(CMAKE_BUILD_TYPE Debug) #Debug、Release、RelWithDebInfo、MinSizeRel

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/ccbase/inc/")

execute_process(COMMAND ar -x libccbase.a WORKING_DIRECTORY ccbase/lib)
file(GLOB CCBASE ccbase/lib/*.o)
find_library(CCBASE_A ccbase ./ccbase/lib NO_DEFAULT_PATH)

#add_subdirectory(libazrz)
#add_subdirectory(testazrz)
# add_subdirectory (demo)
# add_subdirectory (demo-ks)
#add_subdirectory (demo-u50)
# add_subdirectory (demo-boost)

# add_subdirectory(deps/licensecxx)
add_subdirectory(libjxkr)
#add_subdirectory (demo-new)