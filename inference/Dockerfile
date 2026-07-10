FROM vllm/vllm-openai:latest

# vLLM serves OpenAI-compatible API
# Model should be mounted at /models
# Example: docker run --gpus all -v ./outputs/merged:/models -p 8001:8001 cyber-inference

EXPOSE 8001

CMD ["--model", "/models/merged", "--port", "8001", "--max-model-len", "8192", "--gpu-memory-utilization", "0.90", "--dtype", "bfloat16", "--enforce-eager"]
