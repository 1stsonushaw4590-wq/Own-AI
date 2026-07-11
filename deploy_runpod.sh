#!/usr/bin/env bash
# RunPod Deployment Script for 7B Cyber-LLM Training

set -e

# =======================
# CONFIGURATION
# =======================
REPO_URL="https://github.com/1stsonushaw4590-wq/Own-AI.git"
BRANCH="master"
PROJECT_DIR="/workspace/Own-AI"
DATASET_PATH="data/cyber_train_merged.jsonl"
MODEL_NAME="Qwen/Qwen2.5-Coder-7B-Instruct"
OUTPUT_DIR="/workspace/outputs/qwen25-coder-7b-cyber"

# GPU Options (choose one):
# GPU_TYPE="RTX 3090"      # $0.44/hr, 24GB VRAM
# GPU_TYPE="RTX 4090"      # $0.79/hr, 24GB VRAM (faster)
GPU_TYPE="A10G"           # $0.70/hr, 24GB VRAM (RunPod)
# GPU_TYPE="A100"         # $1.64/hr, 40GB VRAM (fastest)

echo "========================================"
echo "RunPod 7B Cyber-LLM Training Deploy"
echo "========================================"
echo "GPU: $GPU_TYPE"
echo "Model: $MODEL_NAME"
echo "Dataset: $DATASET_PATH"
echo "Output: $OUTPUT_DIR"
echo ""

# =======================
# SETUP
# =======================
cd /workspace

# Clone repo
if [ ! -d "$PROJECT_DIR" ]; then
    echo "Cloning repository..."
    git clone -b $BRANCH $REPO_URL $PROJECT_DIR
else
    echo "Updating repository..."
    cd $PROJECT_DIR && git pull origin $BRANCH
fi

cd $PROJECT_DIR

# Install dependencies
echo "Installing Python dependencies..."
pip install -q --upgrade pip
pip install -q -r training/requirements.txt
pip install -q bitsandbytes accelerate peft trl wandb

# Check GPU
echo "GPU Info:"
nvidia-smi

# =======================
# TRAINING
# =======================
echo "Starting 7B QLoRA training..."
export PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:512

DATASET_PATH=data/cyber_train_merged.jsonl \
MODEL_NAME=Qwen/Qwen2.5-Coder-7B-Instruct \
OUTPUT_DIR=$OUTPUT_DIR \
python3 training/train_7b_gpu.py 2>&1 | tee /workspace/training.log

# =======================
# MERGE & QUANTIZE
# =======================
echo "Merging adapter and quantizing to GGUF..."

cd $PROJECT_DIR
python3 training/merge_and_quantize.py \
    --base $MODEL_NAME \
    --adapter $OUTPUT_DIR/adapter \
    --output $OUTPUT_DIR/merged \
    --gguf $OUTPUT_DIR/gguf \
    --quant q4_k_m

# =======================
# VERIFY GGUF
# =======================
echo "Verifying GGUF model..."
ls -la $OUTPUT_DIR/gguf/

# Test inference
echo "Testing inference..."
timeout 30s llama-server \
    -m $OUTPUT_DIR/gguf/cyber-llm-q4_k_m.gguf \
    --alias cyber-llm \
    --host 127.0.0.1 \
    --port 8080 \
    --threads 8 \
    --ctx-size 8192 \
    --log-file /tmp/test_server.log &

sleep 10

curl -s -X POST http://127.0.0.1:8080/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d '{"model": "cyber-llm", "messages": [{"role": "user", "content": "What is SQL injection?"}], "max_tokens": 200}' | jq -r '.choices[0].message.content'

echo ""
echo "========================================"
echo "Training Complete!"
echo "GGUF Model: $OUTPUT_DIR/gguf/cyber-llm-q4_k_m.gguf"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Download GGUF from RunPod volume"
echo "2. Run locally: llama-server -m cyber-llm-q4_k_m.gguf --port 8080"
echo "3. Test orchestrator: ./agent/cpp/build/cyber_orchestrator --prompt \"scan 127.0.0.1\""