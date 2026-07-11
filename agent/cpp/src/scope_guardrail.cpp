#include "cyber_orchestrator.hpp"
#include <fstream>
#include <nlohmann/json.hpp>

namespace cyber {

ScopeGuardrail::ScopeGuardrail(const std::string& scope_file) {
    std::ifstream f(scope_file);
    if (!f) return;
    json j; f >> j;
    if (j.contains("allowed_targets")) {
        for (const auto& t : j["allowed_targets"]) {
            allowed_targets_.insert(t.get<std::string>());
        }
    }
}

bool ScopeGuardrail::check(const std::string& tool_name, const nlohmann::json& args) const {
    static const std::unordered_set<std::string> active_tools = {
        "nmap_scan", "nikto_scan", "sqlmap_scan", "hydra_brute", "metasploit_exploit",
        "gobuster_dir", "subfinder_enum", "httpx_probe", "ffuf_fuzz", "dalfox_xss"
    };
    if (active_tools.find(tool_name) == active_tools.end()) return true;
    
    std::string target;
    if (args.contains("target")) target = args["target"].get<std::string>();
    else if (args.contains("host")) target = args["host"].get<std::string>();
    else if (args.contains("url")) target = args["url"].get<std::string>();
    else if (args.contains("domain")) target = args["domain"].get<std::string>();
    if (target.empty()) return false;
    
    for (const auto& allowed : allowed_targets_) {
        if (target.find(allowed) != std::string::npos) return true;
    }
    return false;
}

} // namespace cyber