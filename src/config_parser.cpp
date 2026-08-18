#include "fileguard/config_parser.hpp"

#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>

namespace fileguard {

namespace {

using nlohmann::json;

Result<Operation> parse_operation(const json& j) {
    if (!j.is_string()) {
        return err("'operation' must be a string");
    }
    const std::string op = j.get<std::string>();
    if (op == "OPEN") return Operation::Open;
    return err("unsupported operation '" + op + "' (MVP supports OPEN only)");
}

Result<Action> parse_action(const json& j) {
    if (!j.is_string()) return err("'action' must be a string");
    const std::string a = j.get<std::string>();
    if (a == "ALLOW") return Action::Allow;
    if (a == "DENY") return Action::Deny;
    return err("invalid action '" + a + "' (expected ALLOW or DENY)");
}

Result<ProcessIdentity> parse_process(const json& j) {
    ProcessIdentity proc;
    if (!j.is_object()) {
        return err("'process' must be an object with 'type' and 'value'");
    }
    const std::string type = j.value("type", "");
    if (type == "exe_path") {
        proc.type = ProcessIdentityType::ExePath;
    } else {
        return err("unsupported process identity type '" + type +
                   "' (MVP supports exe_path only)");
    }
    const auto value = j.find("value");
    if (value == j.end() || !value->is_string() || value->get<std::string>().empty()) {
        return err("'process.value' must be a non-empty path");
    }
    proc.value = value->get<std::string>();
    if (proc.value.front() != '/') {
        return err("process path must be absolute: '" + proc.value + "'");
    }
    return proc;
}

}  // namespace

Result<Policy> ConfigParser::from_json(std::string_view json_text) {
    json root;
    try {
        root = json::parse(json_text.begin(), json_text.end());
    } catch (const json::parse_error& e) {
        return err(std::string("policy JSON parse error: ") + e.what());
    }

    if (!root.is_object()) {
        return err("policy must be a JSON object");
    }

    const int32_t version = root.value("version", 0);

    Action default_action = Action::Deny;
    if (root.contains("defaults")) {
        const auto& defaults = root["defaults"];
        if (!defaults.is_object()) return err("'defaults' must be an object");
        if (defaults.contains("action")) {
            auto a = parse_action(defaults["action"]);
            if (!a) return err(a.error());
            default_action = *a;
        }
    }

    std::vector<ResourceIdentity> protected_resources;
    if (root.contains("protected_resources")) {
        const auto& list = root["protected_resources"];
        if (!list.is_array()) {
            return err("'protected_resources' must be an array");
        }
        for (const auto& item : list) {
            if (!item.is_object()) {
                return err("each protected resource must be an object");
            }
            const std::string path = item.value("path", "");
            if (path.empty() || path.front() != '/') {
                return err("protected resource path must be absolute: '" + path + "'");
            }
            ResourceIdentity res;
            res.path = path;
            if (item.contains("operation")) {
                auto op = parse_operation(item["operation"]);
                if (!op) return err(op.error());
                res.operation = *op;
            }
            protected_resources.push_back(std::move(res));
        }
    }

    std::vector<PolicyRule> rules;
    if (root.contains("rules")) {
        const auto& list = root["rules"];
        if (!list.is_array()) {
            return err("'rules' must be an array");
        }
        for (const auto& item : list) {
            if (!item.is_object()) {
                return err("each rule must be an object");
            }
            PolicyRule rule;
            rule.id = item.value("id", "");
            rule.resource.path = item.value("resource", "");
            if (item.contains("operation")) {
                auto op = parse_operation(item["operation"]);
                if (!op) return err(op.error());
                rule.operation = *op;
            }
            if (item.contains("process")) {
                auto proc = parse_process(item["process"]);
                if (!proc) return err(proc.error());
                rule.process = *proc;
            }
            if (item.contains("action")) {
                auto a = parse_action(item["action"]);
                if (!a) return err(a.error());
                rule.action = *a;
            }
            rules.push_back(std::move(rule));
        }
    }

    Policy policy(version, default_action, std::move(protected_resources),
                  std::move(rules));
    if (auto v = policy.validate(); !v) {
        return err(v.error());
    }
    return policy;
}

Result<Policy> ConfigParser::from_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return err("cannot open policy file '" + path + "'");
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    if (in.bad()) {
        return err("error reading policy file '" + path + "'");
    }
    return from_json(ss.str());
}

}  // namespace fileguard
