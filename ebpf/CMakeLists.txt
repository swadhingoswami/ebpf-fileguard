# eBPF backend build (Linux only; included by the top-level CMakeLists when
# ENABLE_EBPF=ON).
#
# Requires on the build host:
#   * libbpf (>= 0.7)      -> pkg-config module `libbpf`
#   * bpftool              -> `btf dump` + `gen skeleton`
#   * clang with BPF target
#   * a running Linux kernel with /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF)
#
# Pipeline:
#   /sys/kernel/btf/vmlinux --bpftool btf dump--> vmlinux.h
#   vmlinux.h + fileguard.bpf.c --clang -target bpf--> fileguard.bpf.o
#   fileguard.bpf.o --bpftool gen skeleton--> fileguard.skel.h
#   fileguard.skel.h + src/ebpf_manager_linux.cpp --libbpf--> fileguard_ebpf_backend

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf>=0.7)

find_program(BPFTOOL bpftool)
if(NOT BPFTOOL)
    message(FATAL_ERROR
        "bpftool not found. Install it (e.g. `apt install bpftool` or build "
        "from tools/bpf/bpftool) — it is required to generate vmlinux.h and "
        "the libbpf skeleton.")
endif()

if(NOT EXISTS /sys/kernel/btf/vmlinux)
    message(FATAL_ERROR
        "/sys/kernel/btf/vmlinux not found. The running kernel lacks BTF "
        "(CONFIG_DEBUG_INFO_BTF). Enable it and rebuild, or run on a "
        "distribution kernel that ships BTF (most modern distros do).")
endif()

# Target architecture for the BPF program (bpf_tracing.h needs __TARGET_ARCH_*).
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(BPF_TARGET_ARCH x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(BPF_TARGET_ARCH arm64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(s390x|s390)$")
    set(BPF_TARGET_ARCH s390)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(riscv64|riscv)$")
    set(BPF_TARGET_ARCH riscv)
else()
    message(FATAL_ERROR "Unsupported architecture for eBPF: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# ---- generated artifacts ----
set(VMLINUX_H   ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)
set(BPF_OBJ     ${CMAKE_CURRENT_BINARY_DIR}/fileguard.bpf.o)
set(SKEL_H      ${CMAKE_CURRENT_BINARY_DIR}/fileguard.skel.h)

# The BPF program compiles freestanding: -nostdinc drops the host libc
# (glibc's <stdint.h> is unusable under -target bpf); clang's own freestanding
# headers (stdint/stdbool/stddef) come from the resource dir.
execute_process(COMMAND clang -print-resource-dir
                OUTPUT_VARIABLE CLANG_RESOURCE_DIR
                OUTPUT_STRIP_TRAILING_WHITESPACE)

add_custom_command(
    OUTPUT ${VMLINUX_H}
    COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fileguard.bpf.c
    COMMENT "Generating vmlinux.h from running kernel BTF"
    VERBATIM)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND clang -g -O2 -target bpf -nostdinc -D__TARGET_ARCH_${BPF_TARGET_ARCH}
            -I${CMAKE_CURRENT_BINARY_DIR}
            -I${CMAKE_CURRENT_SOURCE_DIR}
            -I${CMAKE_SOURCE_DIR}/include/fileguard
            -isystem ${CLANG_RESOURCE_DIR}/include
            -idirafter ${LIBBPF_INCLUDE_DIRS}
            -c ${CMAKE_CURRENT_SOURCE_DIR}/fileguard.bpf.c
            -o ${BPF_OBJ}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fileguard.bpf.c ${VMLINUX_H}
            ${CMAKE_SOURCE_DIR}/include/fileguard/abi.h
    COMMENT "Compiling fileguard.bpf.c (clang -target bpf)"
    VERBATIM)

add_custom_command(
    OUTPUT ${SKEL_H}
    COMMAND ${BPFTOOL} gen skeleton ${BPF_OBJ} > ${SKEL_H}
    DEPENDS ${BPF_OBJ}
    COMMENT "Generating libbpf skeleton (fileguard.skel.h)"
    VERBATIM)

add_custom_target(fileguard_bpf_generated
    DEPENDS ${VMLINUX_H} ${BPF_OBJ} ${SKEL_H})

# ---- backend static library ----
add_library(fileguard_ebpf_backend STATIC
    ${CMAKE_SOURCE_DIR}/src/ebpf_manager_linux.cpp)

target_include_directories(fileguard_ebpf_backend PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}             # fileguard.skel.h
    ${CMAKE_SOURCE_DIR}/include             # fileguard/*.hpp
    ${CMAKE_SOURCE_DIR}/include/fileguard   # abi.h
    ${LIBBPF_INCLUDE_DIRS})

target_link_libraries(fileguard_ebpf_backend PRIVATE PkgConfig::LIBBPF)

target_compile_options(fileguard_ebpf_backend PRIVATE
    -Wall -Wextra -Wpedantic -Wshadow -Werror)

add_dependencies(fileguard_ebpf_backend fileguard_bpf_generated)
