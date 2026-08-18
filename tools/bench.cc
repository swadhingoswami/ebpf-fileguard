// fileguard-bench — open(2) latency/throughput micro-benchmark.
//
// Usage:
//   fileguard-bench -f /protected/secret.txt -n 100000 [-p N] [-o out.csv] [-r N]
//
//   -f FILE   file to open (should be a *protected* resource to exercise the
//             enforcement path when FileGuard is running)
//   -n N      number of open+close iterations (default 100000)
//   -p N      optional pacing in nanoseconds between iterations, to reach a
//             target event rate (e.g. -p 10000 ~ 100k opens/sec)
//   -o FILE   write one CSV row with results
//   -q        quiet (no CSV file, just stdout)
//
// Run three scenarios and compare:
//   1. baseline:       no FileGuard installed
//   2. monitoring:     FileGuard installed with policy that ALLOWs this process
//   3. enforcement:    FileGuard installed, policy default-DENY with a
//                      matching allow rule (same as #2, but measure the deny
//                      path too with an unauthorized tool)
//
// See docs/10-performance.md for the full methodology.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include <fcntl.h>
#include <unistd.h>

namespace {

int64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

void usage(const char* prog) {
    std::cerr << "usage: " << prog
              << " -f FILE -n N [-p pacing_ns] [-o csv] [-q]\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::string file;
    int64_t n = 100000;
    int64_t pacing_ns = 0;
    std::string csv;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            file = argv[++i];
        } else if (std::strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            n = std::atoll(argv[++i]);
        } else if (std::strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            pacing_ns = std::atoll(argv[++i]);
        } else if (std::strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            csv = argv[++i];
        } else if (std::strcmp(argv[i], "-q") == 0) {
            csv.clear();
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (file.empty() || n <= 0) {
        usage(argv[0]);
        return 2;
    }

    // Warm up (page cache + LSM decision path).
    for (int i = 0; i < 1000; ++i) {
        const int fd = ::open(file.c_str(), O_RDONLY);
        if (fd >= 0) ::close(fd);
    }

    int failed = 0;
    const int64_t start = now_ns();
    for (int64_t i = 0; i < n; ++i) {
        const int fd = ::open(file.c_str(), O_RDONLY);
        if (fd < 0) {
            ++failed;
        } else {
            ::close(fd);
        }
        if (pacing_ns > 0) {
            std::this_thread::sleep_for(std::chrono::nanoseconds(pacing_ns));
        }
    }
    const int64_t elapsed = now_ns() - start;
    const double secs = static_cast<double>(elapsed) / 1e9;
    const double per_op_us = static_cast<double>(elapsed) / static_cast<double>(n) / 1e3;
    const double throughput = static_cast<double>(n) / secs;

    std::printf("file=%s iterations=%lld failed=%d\n", file.c_str(),
                static_cast<long long>(n), failed);
    std::printf("total_time=%.6fs avg_per_open=%.3fus throughput=%.0f opens/s\n",
                secs, per_op_us, throughput);

    if (!csv.empty()) {
        std::ofstream out(csv, std::ios::app);
        if (out) {
            out << file << ',' << n << ',' << failed << ',' << per_op_us << ','
                << throughput << ',' << elapsed << '\n';
        }
    }
    return failed == 0 ? 0 : 1;
}
