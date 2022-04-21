cmake_minimum_required(VERSION 3.16)
project(UA2F C)

set(CMAKE_C_STANDARD 11)

include_directories("/usr/local/include")

add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)

add_executable(ua2f src/ua2f.c)

target_link_libraries(ua2f mnl netfilter_queue ipset)

install(TARGETS ua2f RUNTIME DESTINATION bin)
