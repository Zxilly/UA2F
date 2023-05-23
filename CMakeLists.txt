cmake_minimum_required(VERSION 3.16)
project(UA2F C)

# Find Git
find_package(Git)

# Get Git commit hash
if(GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_COMMIT
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
else()
    set(GIT_COMMIT "unknown")
endif()

# Get Git branch
if(GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} branch --show-current
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_BRANCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
else()
    set(GIT_BRANCH "unknown")
endif()

# Get Git tag
if(GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --abbrev=0
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_TAG
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
else()
    set(GIT_TAG "unknown")
endif()

if(NOT UA2F_VERSION)
    set(UA2F_VERSION "unknown")
endif()

# Define macros
add_compile_definitions(UA2F_GIT_COMMIT="${GIT_COMMIT}")
add_compile_definitions(UA2F_GIT_BRANCH="${GIT_BRANCH}")
add_compile_definitions(UA2F_GIT_TAG="${GIT_TAG}")
add_compile_definitions(UA2F_VERSION="${UA2F_VERSION}")

include(CheckSymbolExists)
check_symbol_exists(__malloc_hook "malloc.h" IS_LIBC_GLIBC)

if (IS_LIBC_GLIBC)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
else ()
    message(STATUS "AddressSanitizer is disabled.")
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-gc-sections")

add_compile_options(-std=gnu17)

if(UA2F_CUSTOM_USER_AGENT)
    if(NOT UA2F_USER_AGENT_STRING)
        message(FATAL_ERROR "UA2F_USER_AGENT_STRING is not set")
    endif()
    add_compile_definitions(UA2F_CUSTOM_UA="${UA2F_USER_AGENT_STRING}")
endif()

add_executable(ua2f
        src/ua2f.c
        src/statistics.c
        src/util.c
        src/cache.c
        src/handler.c
        src/cli.c
        src/third/nfqueue-mnl.c)

target_link_libraries(ua2f mnl netfilter_queue pthread nfnetlink)

install(TARGETS ua2f RUNTIME DESTINATION bin)
