#ifndef CYBER_ORCHESTRATOR_HPP
#define CYBER_ORCHESTRATOR_HPP

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <memory>
#include <nlohmann/json.hpp>

namespace cyber {

using json = nlohmann::json;

// ---- ToolSpec ----
struct ToolSpec {
    std::string name;
    std::string description;
    std::string command_template;
    int timeout_ms = 30000;
    bool requires_scope_check = true;
};

// ---- ToolResult ----
struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
};

// ---- ToolExecutor ----
class ToolExecutor {
public:
    explicit ToolExecutor(const std::string& tools_file);
    ToolResult execute(const std::string& tool_name, const nlohmann::json& args);

private:
    std::unordered_map<std::string, ToolSpec> tools_;
};

// ---- ScopeGuardrail ----
class ScopeGuardrail {
public:
    explicit ScopeGuardrail(const std::string& scope_file);
    bool check(const std::string& tool_name, const nlohmann::json& args) const;

private:
    std::unordered_set<std::string> allowed_targets_;
};

// ---- LlamaClient ----
class LlamaClient {
public:
    explicit LlamaClient(const std::string& base_url, const std::string& model);
    ~LlamaClient();
    std::string chat(const std::vector<std::pair<std::string, std::string>>& messages,
                     const std::vector<nlohmann::json>& tools);

private:
    std::string base_url_;
    std::string model_;
};

// ---- Orchestrator ----
class Orchestrator {
public:
    Orchestrator(const std::string& base_url,
                 const std::string& model,
                 const std::string& tools_file,
                 const std::string& scope_file);
    ~Orchestrator() = default;

    std::string run(const std::string& user_prompt, int max_turns = 8);
    std::string run_bug_bounty(const std::string& target, int max_turns = 15);

private:
    void load_tools(const std::string& tools_file);
    std::string get_system_prompt(bool bug_bounty_mode);
    
    std::unique_ptr<LlamaClient> llama_;
    std::unique_ptr<ToolExecutor> executor_;
    std::unique_ptr<ScopeGuardrail> guardrail_;
    std::vector<nlohmann::json> tool_schemas_;
};

} // namespace cyber

#endif // CYBER_ORCHESTRATOR_HPP