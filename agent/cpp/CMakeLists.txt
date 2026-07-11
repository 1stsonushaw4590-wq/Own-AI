cmake_minimum_required(VERSION 3.16...3.28)
project(cyber_llm_orchestrator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(nlohmann_json 3.11 REQUIRED)
find_package(CURL REQUIRED)

add_executable(cyber_orchestrator
    src/main.cpp
    src/orchestrator.cpp
    src/llama_client.cpp
    src/scope_guardrail.cpp
)

target_link_libraries(cyber_orchestrator PRIVATE
    Threads::Threads
    nlohmann_json::nlohmann_json
    ${CURL_LIBRARIES}
)

target_include_directories(cyber_orchestrator PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CURL_INCLUDE_DIRS}
)

# Installation
install(TARGETS cyber_orchestrator
        RUNTIME DESTINATION bin)