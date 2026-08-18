#pragma once

#include <string_view>

#include "core_utils.hpp"
#include "policy.hpp"

namespace fileguard {

// Parses a policy from its JSON textual representation into a validated
// Policy object. This is the single input path for policy configuration; the
// daemon validates a policy here before it is ever compiled or installed.
//
// JSON schema (MVP):
//
//   {
//     "version": 1,
//     "defaults": { "action": "DENY" },
//     "protected_resources": [
//         { "path": "/protected/secret.txt", "operation": "OPEN" }
//     ],
//     "rules": [
//         {
//             "id": "allow-backup-agent",
//             "resource": "/protected/secret.txt",
//             "operation": "OPEN",
//             "process": { "type": "exe_path", "value": "/usr/local/bin/backup-agent" },
//             "action": "ALLOW"
//         }
//     ]
//   }
//
// See docs/05-policy-model.md for the rationale and evolution path.
class ConfigParser {
public:
    static Result<Policy> from_json(std::string_view json_text);
    static Result<Policy> from_file(const std::string& path);
};

}  // namespace fileguard
