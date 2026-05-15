cmake_minimum_required(VERSION 3.14)
project(miniudp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/include)

set(COMMON_SRC
    src/proto.c
    src/conn.c
    src/io_loop.c
    src/timer.c
    src/checksum.c
    src/log.c
    src/util.c
)

add_executable(miniudp_client src/main_client.c ${COMMON_SRC})
add_executable(miniudp_server src/main_server.c ${COMMON_SRC})

if (MSVC)
    add_compile_options(/utf-8)
endif()

if (WIN32)
    target_link_libraries(miniudp_client ws2_32)
    target_link_libraries(miniudp_server ws2_32)
endif()
