cmake_minimum_required(VERSION 3.16)
project(UA2F C)

set(CMAKE_C_STANDARD 11)

include_directories("/usr/local/include")

add_executable(ua2f src/ua2f.c)
add_executable(test test/test.c)
add_executable(nf-queue src/nf-queue.c)
add_executable(clocktest test/clocktest.c)
add_executable(nfct-event src/nfct-event.c)
add_executable(nfq test/nfq.c)

target_link_libraries(ua2f mnl netfilter_queue ipset)
target_link_libraries(nfct-event mnl netfilter_conntrack)
target_link_libraries(nf-queue mnl netfilter_queue ipset)
target_link_libraries(test mnl netfilter_queue ipset)
target_link_libraries(clocktest mnl netfilter_queue)
target_link_libraries(nfq mnl netfilter_queue)
