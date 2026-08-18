#pragma once

#include <optional>
#include <string>
#include <vector>

#include "core_utils.hpp"

namespace fileguard {

// Result of parsing the guardctl command line.
struct CliArgs {
    std::string command;             // serve|validate|load|list|status|events|stop
    std::string policy_file;         // policy load/validate/serve
    std::string runtime_dir = "/tmp/fileguard";
    std::string log_file;            // serve --log
    bool daemonize = false;          // serve --daemon
    bool json_output = false;        // events --json
    int event_count = -1;            // events --count
    bool force = false;              // policy load --force
};

// Parses argv into a command; returns a descriptive error for bad usage.
Result<CliArgs> parse_cli(int argc, char** argv);

// Executes the parsed command and returns the process exit code.
int run_cli(const CliArgs& args);

// Convenience entry point used by main().
int guardctl_main(int argc, char** argv);

}  // namespace fileguard
