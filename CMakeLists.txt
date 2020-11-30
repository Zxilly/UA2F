cmake_minimum_required(VERSION 3.16)
project(UA2F C)

set(CMAKE_C_STANDARD 11)

add_executable(main src/ua2f.c)
add_executable(test test/test.c)
add_executable(nf-queue src/nf-queue.c)
add_executable(clocktest test/clocktest.c)
target_link_libraries(main mnl netfilter_queue)
target_link_libraries(nf-queue mnl netfilter_queue)
target_link_libraries(test mnl netfilter_queue)
target_link_libraries(clocktest mnl netfilter_queue)