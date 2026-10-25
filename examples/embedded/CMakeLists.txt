# GENERIC-C 임베디드 샘플: proto_parser 정적 라이브러리.
# HAL 정의는 의도적으로 포함하지 않는다(펌웨어에서는 벤더 HAL 이 제공).
cmake_minimum_required(VERSION 3.13)
project(proto_parser C)

add_library(proto STATIC proto_parser.c)
target_include_directories(proto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
