cmake_minimum_required(VERSION 3.16)
project(UA2F C)

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

add_executable(ua2f
        src/ua2f.c
        src/statistics.c
        src/util.c
        src/cache.c
        src/handler.c
        src/third/nfqueue-mnl.c)

target_link_libraries(ua2f mnl netfilter_queue pthread nfnetlink)

install(TARGETS ua2f RUNTIME DESTINATION bin)
