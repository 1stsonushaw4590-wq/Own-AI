#include "cyber_orchestrator.hpp"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    std::string base_url = "http://127.0.0.1:8080/v1";
    std::string model = "cyber-llm";
    std::string tools_file = "agent/tools/tools.json";
    std::string scope_file = "agent/config/scope.json";
    std::string prompt;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--base-url" && i + 1 < argc) base_url = argv[++i];
        else if (arg == "--model" && i + 1 < argc) model = argv[++i];
        else if (arg == "--tools" && i + 1 < argc) tools_file = argv[++i];
        else if (arg == "--scope" && i + 1 < argc) scope_file = argv[++i];
        else if (arg == "--prompt" && i + 1 < argc) prompt = argv[++i];
    }
    
    if (prompt.empty()) {
        std::cerr << "Usage: " << argv[0] << " [options] --prompt \"your prompt\"\n"
                  << "Options:\n"
                  << "  --base-url URL     llama-server URL (default: http://127.0.0.1:8080/v1)\n"
                  << "  --model NAME       Model name (default: cyber-llm)\n"
                  << "  --tools FILE       tools.json path\n"
                  << "  --scope FILE       scope.json path\n"
                  << "  --prompt TEXT      User prompt (required)\n";
        return 1;
    }
    
    try {
        cyber::Orchestrator orch("http://127.0.0.1:8080/v1", "cyber-llm", "agent/tools/tools.json", "agent/config/scope.json");
        std::string result = orch.run(prompt);
        std::cout << result << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}