#include "cyber_orchestrator.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <regex>
#include <nlohmann/json.hpp>

namespace cyber {

using json = nlohmann::json;

// ---- ToolExecutor ----
ToolExecutor::ToolExecutor(const std::string& tools_file) {
    std::ifstream f(tools_file);
    if (!f) return;
    json j; f >> j;
    if (j.contains("tools")) {
        for (const auto& t : j["tools"]) {
            json func = t.value("function", t);
            ToolSpec spec;
            spec.name = func.value("name", "");
            spec.description = func.value("description", "");
            spec.command_template = func.value("command", "");
            spec.timeout_ms = func.value("timeout_sec", 30) * 1000;
            spec.requires_scope_check = func.value("scope_guardrail", true);
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
    
    json merged_args = args;
    
    if (tool_name == "nmap_scan") {
        if (!merged_args.contains("scan_type")) merged_args["scan_type"] = "connect";
        if (!merged_args.contains("ports")) merged_args["ports"] = "1-1000";
        std::string scan_type = merged_args.value("scan_type", "connect");
        std::string scan_flag;
        if (scan_type == "syn") scan_flag = "S";
        else if (scan_type == "connect") scan_flag = "T";
        else if (scan_type == "service") scan_flag = "V";
        else scan_flag = "T";
        merged_args["scan_type"] = scan_flag;
    }
    if (tool_name == "nikto_scan") {
        if (!merged_args.contains("ssl")) merged_args["ssl"] = false;
        bool ssl = merged_args.value("ssl", false);
        merged_args["ssl_flag"] = ssl ? " -ssl" : "";
    }
    if (tool_name == "semgrep_scan") {
        if (!merged_args.contains("config")) merged_args["config"] = "auto";
    }
    if (tool_name == "nuclei_scan") {
        if (!merged_args.contains("templates")) merged_args["templates"] = "technologies";
    }
    
    for (auto& [key, val] : merged_args.items()) {
        std::string placeholder = "{" + key + "}";
        std::string replacement = val.is_string() ? val.get<std::string>() : val.dump();
        size_t pos = 0;
        while ((pos = cmd.find(placeholder, pos)) != std::string::npos) {
            cmd.replace(pos, placeholder.length(), replacement);
            pos += replacement.length();
        }
    }
    
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

// ---- Orchestrator ----
Orchestrator::Orchestrator(const std::string& base_url, const std::string& model,
                           const std::string& tools_file, const std::string& scope_file)
    : llama_(std::make_unique<LlamaClient>(base_url, model)),
      executor_(std::make_unique<ToolExecutor>(tools_file)),
      guardrail_(std::make_unique<ScopeGuardrail>(scope_file)) {
    load_tools(tools_file);
}

void Orchestrator::load_tools(const std::string& tools_file) {
    std::ifstream f(tools_file);
    if (!f) return;
    json j; f >> j;
    if (j.contains("tools")) {
        for (const auto& t : j["tools"]) {
            json func = t.value("function", t);
            nlohmann::json schema;
            schema["type"] = "function";
            schema["function"] = {
                {"name", func.value("name", "")},
                {"description", func.value("description", "")},
                {"parameters", func.value("parameters", json::object())}
            };
            tool_schemas_.push_back(schema);
        }
    }
}

std::string Orchestrator::run(const std::string& user_prompt, int max_turns) {
    bool bug_bounty_mode = user_prompt.find("bug bounty") != std::string::npos || 
                           user_prompt.find("bounty") != std::string::npos ||
                           user_prompt.find("full assessment") != std::string::npos;

    std::vector<std::pair<std::string, std::string>> messages;
    std::string system_prompt = get_system_prompt(bug_bounty_mode);
    messages.emplace_back("system", system_prompt);
    messages.emplace_back("user", user_prompt);
    
    for (int turn = 0; turn < max_turns; ++turn) {
        std::string response = llama_->chat(messages, tool_schemas_);
        
        try {
            json resp = json::parse(response);
            if (resp.contains("choices") && !resp["choices"].empty()) {
                json choice = resp["choices"][0];
                if (choice.contains("message")) {
                    json msg = choice["message"];
                    std::string content = msg.value("content", "");
                    messages.emplace_back("assistant", content);
                    
                    if (msg.contains("tool_calls")) {
                        for (const auto& tc : msg["tool_calls"]) {
                            std::string tool_name = tc["function"]["name"];
                            json args = tc["function"]["arguments"];
                            
                            if (!guardrail_->check(tool_name, args)) {
                                messages.emplace_back("tool", "SCOPE VIOLATION: Target not in allowed scope");
                                continue;
                            }
                            
                            ToolResult result = executor_->execute(tool_name, args);
                            std::string result_str = result.success ? result.output : "ERROR: " + result.error;
                            messages.emplace_back("tool", result_str);
                        }
                        continue;
                    }
                    
                    std::regex tool_call_regex(R"(```json\s*[\r\n](\{[\s\S]*?\})\s*[\r\n]```)");
                    std::smatch match;
                    bool tool_called = false;
                    if (std::regex_search(content, match, tool_call_regex)) {
                        try {
                            json tool_call = json::parse(match[1].str());
                            if (tool_call.contains("name") && tool_call.contains("arguments")) {
                                std::string tool_name = tool_call["name"];
                                json args = tool_call["arguments"];
                                
                                if (!guardrail_->check(tool_name, args)) {
                                    messages.emplace_back("tool", "SCOPE VIOLATION: Target not in allowed scope");
                                    tool_called = true;
                                } else {
                                    ToolResult result = executor_->execute(tool_name, args);
                                    std::string result_str = result.success ? result.output : "ERROR: " + result.error;
                                    messages.emplace_back("tool", result_str);
                                    tool_called = true;
                                }
                            }
                        } catch (...) {}
                    }
                    
                    if (!tool_called) {
                        try {
                            json maybe_tool = json::parse(content);
                            if (maybe_tool.contains("name") && maybe_tool.contains("arguments")) {
                                std::string tool_name = maybe_tool["name"];
                                json args = maybe_tool["arguments"];
                                
                                if (!guardrail_->check(tool_name, args)) {
                                    messages.emplace_back("tool", "SCOPE VIOLATION: Target not in allowed scope");
                                    tool_called = true;
                                } else {
                                    ToolResult result = executor_->execute(tool_name, args);
                                    std::string result_str = result.success ? result.output : "ERROR: " + result.error;
                                    messages.emplace_back("tool", result_str);
                                    tool_called = true;
                                }
                            }
                        } catch (...) {}
                    }
                    
                    if (tool_called) {
                        continue;
                    }
                    
                    return content;
                }
            }
        } catch (...) {
            return response;
        }
    }
    
    return "Max turns reached without final answer";
}

std::string Orchestrator::run_bug_bounty(const std::string& target, int max_turns) {
    std::string prompt = "Perform a complete bug bounty assessment on " + target + 
                         ". Follow the bug bounty workflow: reconnaissance, vulnerability analysis, exploitation (if authorized), and reporting.";
    return run(prompt, max_turns);
}

std::string Orchestrator::get_system_prompt(bool bug_bounty_mode) {
    if (bug_bounty_mode) {
        return R"(You are a cybersecurity assistant specialized in bug bounty hunting. 
Follow this bug bounty workflow:

PHASE 1 - RECONNAISSANCE:
- Use nmap_scan for port/service discovery
- Use nuclei_scan with templates: technologies, exposures, misconfigurations
- Use nikto_scan for web server analysis

PHASE 2 - VULNERABILITY ANALYSIS:
- Analyze scan results for vulnerabilities
- Use nuclei_scan with cves, vulnerabilities templates
- Use semgrep_scan for code analysis (if source available)

PHASE 3 - EXPLOITATION (AUTHORIZED ONLY):
- Develop proof-of-concept exploits for confirmed vulnerabilities
- Use metasploit modules if available
- Document impact and severity

PHASE 4 - REPORTING:
- Provide clear vulnerability description
- Include steps to reproduce
- Rate severity (CVSS)
- Suggest remediation

WORKFLOW RULES:
1. When you need a tool, output EXACTLY this format in a markdown code block:
```json
{"name": "tool_name", "arguments": {"param": "value"}}
```
2. After tool executes, you will receive the result. ANALYZE the result and provide your NEXT STEP or FINAL ANSWER.
3. DO NOT call the same tool again unless you need different information.
4. When assessment is complete, provide a comprehensive report.

Available tools:
- nmap_scan: target (string, REQUIRED), scan_type (syn|connect|service, default: connect), ports (string, default: 1-1000)
- nikto_scan: host (string, REQUIRED), ssl (boolean, default: false)
- semgrep_scan: path (string, REQUIRED), config (string, default: auto)
- nuclei_scan: target (string, REQUIRED), templates (string, default: technologies)
- sqlmap_scan: url (string, REQUIRED), data (string, optional), cookie (string, optional)
- metasploit_exploit: module (string, REQUIRED), rhosts (string, REQUIRED), lhost (string, REQUIRED), payload (string, optional)
)";
    }
    return R"(You are a cybersecurity assistant with access to tools. Follow this workflow:

1. When user asks a question, decide if you need a tool
2. If you need a tool, output EXACTLY this format in a markdown code block:
```json
{"name": "tool_name", "arguments": {"param": "value"}}
```
3. After tool executes, you will receive the result. ANALYZE the result and provide a FINAL ANSWER to the user.
4. DO NOT call the same tool again unless you need different information.

Examples:
User: Scan 192.168.1.1
Assistant: ```json
{"name": "nmap_scan", "arguments": {"target": "192.168.1.1", "scan_type": "connect"}}
```
[Tool executes, returns results]
Assistant: The scan of 192.168.1.1 shows ports 22, 80, 443 open. SSH, HTTP, and HTTPS services are running.

User: Check web server at example.com
Assistant: ```json
{"name": "nikto_scan", "arguments": {"host": "example.com", "ssl": false}}
```
[Tool executes, returns results]
Assistant: The Nikto scan of example.com found no critical vulnerabilities. The server is Apache 2.4.41 with standard configuration.

Available tools:
- nmap_scan: target (string, REQUIRED), scan_type (syn|connect|service, default: connect), ports (string, default: 1-1000)
- nikto_scan: host (string, REQUIRED), ssl (boolean, default: false)
- semgrep_scan: path (string, REQUIRED), config (string, default: auto)
- nuclei_scan: target (string, REQUIRED), templates (string, default: technologies)

REMEMBER: After a tool returns results, provide your analysis and final answer. Do NOT call the same tool again.
)";
}

} // namespace cyber