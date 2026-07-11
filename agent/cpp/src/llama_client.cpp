#include "cyber_orchestrator.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <nlohmann/json.hpp>
#include <curl/curl.h>

namespace cyber {

using json = nlohmann::json;

// ---- CurlWriteData ----
struct CurlWriteData {
    std::string buffer;
};

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    auto* data = static_cast<CurlWriteData*>(userp);
    data->buffer.append(static_cast<const char*>(contents), total);
    return total;
}

// ---- LlamaClient ----
LlamaClient::LlamaClient(const std::string& base_url, const std::string& model)
    : base_url_(base_url), model_(model) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

LlamaClient::~LlamaClient() {
    curl_global_cleanup();
}

std::string LlamaClient::chat(const std::vector<std::pair<std::string, std::string>>& messages,
                               const std::vector<nlohmann::json>& tools) {
    json payload;
    payload["model"] = model_;
    payload["messages"] = json::array();
    for (const auto& [role, content] : messages) {
        payload["messages"].push_back({{"role", role}, {"content", content}});
    }
    // Do NOT send tools parameter - use system prompt for tool calling instead
    // if (!tools.empty()) {
    //     payload["tools"] = tools;
    //     payload["tool_choice"] = "auto";
    // }
    payload["stream"] = false;
    payload["temperature"] = 0.2;
    payload["max_tokens"] = 1024;

    std::string body = payload.dump();

    CURL* curl = curl_easy_init();
    if (!curl) return "ERROR: curl init failed";

    CurlWriteData write_data;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, (base_url_ + "/chat/completions").c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        return "ERROR: curl failed: " + std::string(curl_easy_strerror(res));
    }

    return write_data.buffer;
}

} // namespace cyber