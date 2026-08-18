#pragma once

#if defined(__linux__)

#include <cstdint>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>

#include "enforcer.hpp"

namespace fileguard {

// Linux eBPF LSM enforcement backend.
//
// Owns a libbpf skeleton of ebpf/fileguard.bpf.o, the four maps
// (protected/rules/config/events) and the attached `security_file_open` LSM
// program. Policy updates mutate the maps; the ring buffer is polled from
// `run()`.
//
// The concrete implementation lives in src/ebpf_manager_linux.cpp and is only
// built on Linux (see ebpf/CMakeLists.txt), so this header is the only place
// the backend's interface is visible to the portable core.
class LinuxEBPFEnforcer : public IEnforcer {
public:
    explicit LinuxEBPFEnforcer(EnforcerConfig cfg);
    ~LinuxEBPFEnforcer() override;

    LinuxEBPFEnforcer(const LinuxEBPFEnforcer&) = delete;
    LinuxEBPFEnforcer& operator=(const LinuxEBPFEnforcer&) = delete;

    ResultVoid load() override;
    ResultVoid apply_policy(const CompiledPolicy& policy) override;
    EnforcerStatus status() const override;
    void run(std::stop_token stop) override;
    ResultVoid detach() override;

private:
    static int ring_callback(void* ctx, void* data, size_t size);
    ResultVoid clear_map(void* obj, const char* map_name);

    EnforcerConfig cfg_;
    void* skel_ = nullptr;  // struct fileguard_bpf* (opaque)
    void* ring_ = nullptr;  // struct ring_buffer* (opaque)
    mutable std::mutex state_mu_;
    EnforcerStatus status_;
};

}  // namespace fileguard

#endif  // __linux__
