#!/usr/bin/env bash
# build-linux.sh — full build with the eBPF LSM backend enabled.
#
# Requires a Linux host with:
#   * kernel CONFIG_BPF=y, CONFIG_BPF_LSM=y, CONFIG_BPF_RINGBUF=y,
#     CONFIG_DEBUG_INFO_BTF=y (most modern distro kernels qualify)
#   * root, or a user with CAP_BPF/CAP_SYS_ADMIN for runtime tests
#   * build tools + deps (installed here via apt if you allow it)
#
# Usage: ./scripts/build-linux.sh [--install-deps] [--skip-tests]
set -euo pipefail

INSTALL_DEPS=0
SKIP_TESTS=0
for arg in "$@"; do
    case "$arg" in
        --install-deps) INSTALL_DEPS=1 ;;
        --skip-tests) SKIP_TESTS=1 ;;
        *) echo "unknown option: $arg" >&2; exit 1 ;;
    esac
done

if [[ $INSTALL_DEPS -eq 1 ]]; then
    echo "[deps] apt-get install ..."
    sudo apt-get update
    sudo apt-get install -y \
        build-essential cmake clang llvm libbpf-dev bpftool linux-tools-common \
        linux-tools-$(uname -r) libelf-dev zlib1g-dev pkg-config
    # gcc-13 provides <expected> for C++23; use it if available.
    if command -v g++-13 >/dev/null 2>&1; then
        export CXX=g++-13
    fi
fi

echo "[build] cmake configure (ENABLE_EBPF=ON)"
cmake -S . -B build -DENABLE_EBPF=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo

echo "[build] compile"
cmake --build build -j "$(nproc)"

echo "[test] unit tests"
./build/fileguard_tests

if [[ $SKIP_TESTS -eq 0 ]]; then
    echo "[test] kernel preflight"
    if [[ $EUID -ne 0 ]]; then
        echo "  not root — integration tests require root (CAP_BPF). Skipping." >&2
    else
        echo "[test] integration tests (need root)"
        sudo ./scripts/integration-tests.sh
    fi
fi

echo "[ok] build complete. Run the demo with: sudo ./scripts/setup-demo.sh"
