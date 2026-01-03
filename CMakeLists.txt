cmake_minimum_required(VERSION 3.16)
project(socks VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_DEBUG_LIBS ON)
set(Boost_USE_RELEASE_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

find_package(Boost 1.85.0)
include_directories(${Boost_INCLUDE_DIRS})
message(STATUS "Found Boost:    V${Boost_VERSION} (in ${Boost_DIR})")

find_package(fmt 10 REQUIRED)
add_executable(socks main.cpp log.cpp)

target_include_directories(socks PRIVATE ${Boost_INCLUDE_DIRS} third/spdlog/include)

target_link_libraries(socks PRIVATE ${Boost_LIBRARIES} fmt::fmt)
