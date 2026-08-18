#include "fileguard/enforcer.hpp"

#include <atomic>
#include <chrono>
#include <thread>

#if defined(__linux__) && defined(FILEGUARD_HAS_EBPF)
#include "fileguard/ebpf_manager.hpp"
#endif

namespace fileguard {

#if defined(__linux__) && defined(FILEGUARD_HAS_EBPF)

std::unique_ptr<IEnforcer> create_enforcer(const EnforcerConfig& cfg) {
    return std::make_unique<LinuxEBPFEnforcer>(cfg);
}

#else  // !__linux__

// Pass-through stand-in so the controller builds and runs on non-Linux hosts
// (e.g. macOS development). Nothing is attached and nothing is enforced; the
// pipeline simply produces no events. The Linux build uses LinuxEBPFEnforcer.
class NullEnforcer : public IEnforcer {
public:
    explicit NullEnforcer(EnforcerConfig cfg) : cfg_(std::move(cfg)) {}

    ResultVoid load() override {
        status_.backend = "null";
        status_.detail = "null backend: no kernel enforcement (non-Linux host)";
        return ok_v();
    }

    ResultVoid apply_policy(const CompiledPolicy& policy) override {
        status_.policy_version = policy.version;
        status_.protected_count = policy.protected_resources.size();
        status_.rule_count = policy.rules.size();
        status_.attached = false;
        status_.enforcing = false;
        return ok_v();
    }

    EnforcerStatus status() const override { return status_; }

    void run(std::stop_token stop) override {
        while (!stop.stop_requested()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    ResultVoid detach() override {
        status_.attached = false;
        status_.enforcing = false;
        return ok_v();
    }

private:
    EnforcerConfig cfg_;
    EnforcerStatus status_;
};

std::unique_ptr<IEnforcer> create_enforcer(const EnforcerConfig& cfg) {
    return std::make_unique<NullEnforcer>(cfg);
}

#endif  // __linux__ && FILEGUARD_HAS_EBPF

}  // namespace fileguard
