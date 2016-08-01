cmake_minimum_required(VERSION 2.8.11)

project(BIRCH)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --std=c89 -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -pedantic -pedantic-errors -Wunreachable-code -Wformat=2 -fno-builtin -Werror -g -D_GNU_SOURCE")

add_library(birch STATIC birch.c)
add_executable(fortune-bot bots/fortune.c)
target_link_libraries(fortune-bot birch)
