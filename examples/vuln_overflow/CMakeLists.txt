# logosfuzz run 대상: copy_can_label 정적 라이브러리 (main 없는 can_label.c 만 포함)
cmake_minimum_required(VERSION 3.13)
project(vuln_overflow C)

add_library(canlabel STATIC can_label.c)
target_include_directories(canlabel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
