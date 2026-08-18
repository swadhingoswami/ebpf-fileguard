cmake_minimum_required(VERSION 3.24)

project(ebpf_fileguard
    VERSION 0.1.0
    DESCRIPTION "Kernel-Assisted Runtime File Access Control using eBPF LSM and modern C++"
    LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(BUILD_TESTING "Build unit tests" ON)
option(ENABLE_EBPF "Build the Linux eBPF LSM enforcement backend" OFF)
option(ENABLE_SANITIZERS "Enable ASan/UBSan for the core targets" OFF)

# eBPF requires Linux. Hard-disable on other platforms.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(ENABLE_EBPF OFF CACHE BOOL "eBPF backend requires Linux" FORCE)
    message(STATUS "eBPF backend disabled: only supported on Linux")
endif()

if(ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------- dependencies
include(FetchContent)

find_package(Threads REQUIRED)

set(FETCHCONTENT_QUIET OFF)

FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(nlohmann_json)

if(BUILD_TESTING)
    FetchContent_Declare(Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.7.1
        GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(Catch2)
endif()

# ---------------------------------------------------------------- core library
# fileguard_core is fully portable and is the unit-tested heart of the project.
# It has zero dependency on libbpf or Linux-specific headers.
add_library(fileguard_core STATIC
    src/policy.cpp
    src/config_parser.cpp
    src/decision_engine.cpp
    src/policy_compiler.cpp
    src/event_sink.cpp
    src/path_resolver.cpp
    src/enforcer.cpp
    src/controller.cpp
    src/daemon.cpp
    src/cli.cpp)

target_include_directories(fileguard_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(fileguard_core PUBLIC
    nlohmann_json::nlohmann_json
    Threads::Threads)

target_compile_options(fileguard_core PRIVATE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror)

# ---------------------------------------------------------------- eBPF backend
if(ENABLE_EBPF)
    add_subdirectory(ebpf)
    target_link_libraries(fileguard_core PRIVATE fileguard_ebpf_backend)
else()
    message(STATUS "eBPF backend disabled: building with a null enforcement backend")
endif()

# ---------------------------------------------------------------- executables
add_executable(guardctl src/main.cpp)
target_link_libraries(guardctl PRIVATE fileguard_core)

add_executable(backup-agent tools/backup-agent.cc)
target_link_libraries(backup-agent PRIVATE fileguard_core)

add_executable(test-reader tools/test-reader.cc)
target_link_libraries(test-reader PRIVATE fileguard_core)

add_executable(fileguard-bench tools/bench.cc)
target_link_libraries(fileguard-bench PRIVATE fileguard_core)

# ---------------------------------------------------------------- tests
if(BUILD_TESTING)
    enable_testing()

    add_executable(fileguard_tests
        tests/test_config_parser.cpp
        tests/test_decision_engine.cpp
        tests/test_policy_compiler.cpp
        tests/test_policy.cpp
        tests/test_path_resolver.cpp
        tests/test_event_queue.cpp
        tests/test_event_sink.cpp)

    target_link_libraries(fileguard_tests PRIVATE fileguard_core Catch2::Catch2WithMain)
    target_compile_options(fileguard_tests PRIVATE -Wall -Wextra -Wpedantic)

    include(CTest)
    add_test(NAME fileguard_core_tests COMMAND fileguard_tests)
endif()

install(TARGETS guardctl backup-agent test-reader fileguard-bench
    RUNTIME DESTINATION bin)
