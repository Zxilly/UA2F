cmake_minimum_required(VERSION 3.16)
project(UA2F C)

set(CMAKE_C_STANDARD 11)

add_executable(main src/ua2f.c)
target_link_libraries(main mnl netfilter_queue)