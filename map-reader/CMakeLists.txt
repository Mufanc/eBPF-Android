cmake_minimum_required(VERSION 3.26)
project(map-reader)

set(CMAKE_CXX_STANDARD 17)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} PUBLIC log dl)
