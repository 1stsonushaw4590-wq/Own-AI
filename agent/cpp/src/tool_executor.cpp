#include "cyber_orchestrator.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <cstdio>
#include <cstdlib>

namespace cyber {

using json = nlohmann::json;

// ---- ToolExecutor ----
ToolExecutor::ToolExecutor(const std::string& tools_file) {
    std::ifstream f(tools_file);
    if (!f) return;
    json j; f >> j;
    if (j.contains("tools")) {
        for (const auto& t : j["tools"]) {
            ToolSpec spec;
            spec.name = t.value("name", "");
            spec.description = t.value("description", "");
            spec.command_template = t.value("command_template", "");
            spec.timeout_ms = t.value("timeout_ms", 30000);
            spec.requires_scope_check = t.value("requires_scope_check", true);
            tools_[spec.name] = spec;
        }
    }
}

ToolResult ToolExecutor::execute(const std::string& tool_name, const nlohmann::json& args) {
    auto it = tools_.find(tool_name);
    if (it == tools_.end()) {
        return {false, "", "Tool not found: " + tool_name};
    }
    
    const ToolSpec& spec = it->second;
    std::string cmd = spec.command_template;
    
    // Replace placeholders
    for (auto& [key, val] : args.items()) {
        std::string placeholder = "{" + key + "}";
        std::string replacement = val.is_string() ? val.get<std::string>() : val.dump();
        size_t pos = 0;
        while ((pos = cmd.find(placeholder, pos)) != std::string::npos) {
            cmd.replace(pos, placeholder.length(), replacement);
            pos += replacement.length();
        }
    }
    
    // Execute command
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return {false, "", "Failed to execute: " + cmd};
    }
    
    std::string output;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    int status = pclose(pipe);
    bool success = (status == 0);
    
    return {success, output, success ? "" : "Command failed with status: " + std::to_string(status)};
}

} // namespace cyber