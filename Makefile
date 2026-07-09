# Cyber-LLM toolkit — Makefile
# Run `make help` for available targets.
PYTHON ?= python3
VENV   ?= .venv
MODEL  ?= Qwen/Qwen2.5-Coder-7B-Instruct
OUT    ?= outputs/qwen25-coder-7b-cyber
LLAMA_CPP ?= /opt/llama.cpp

.PHONY: help venv deps attack-index corpus dataset llama-index train eval \
        sandbox-build serve-ollama serve-vllm chat streamlit test pipeline \
        benchmark benchmark-mock eval-mock gguf demo-real compose-up \
        compose-down clean install-hooks

help:
	@echo "Cyber-LLM toolkit — available targets:"
	@echo ""
	@echo "  Setup:"
	@echo "    make venv          Create Python virtualenv"
	@echo "    make deps          Install all dependencies (CPU torch + RAG + UI)"
	@echo "    make install-hooks Install pre-commit git hook"
	@echo ""
	@echo "  Data pipeline:"
	@echo "    make data          Full pipeline: attack index + corpus + HF dataset + LlamaIndex"
	@echo "    make attack-index  Download + index MITRE ATT&CK (858 techniques)"
	@echo "    make corpus        Scrape NVD CVE / CWE / HF dataset -> cyber_train.jsonl"
	@echo "    make dataset       Build HF datasets + torch Dataset from corpus"
	@echo "    make llama-index   Build LlamaIndex retrieval store"
	@echo ""
	@echo "  Training (GPU host):"
	@echo "    make train         PEFT QLoRA fine-tune (set MODEL=... OUT=...)"
	@echo "    make gguf          Convert merged model -> GGUF Q4_K_M for Ollama"
	@echo ""
	@echo "  Eval:"
	@echo "    make eval          CyberSecEval eval against merged model"
	@echo "    make eval-mock     CyberSecEval eval with stub model (no GPU)"
	@echo "    make demo-real     Run eval with Qwen2.5-Coder-0.5B on CPU"
	@echo "    make benchmark     Benchmark all 3 models (Qwen/DeepSeek/Llama)"
	@echo "    make benchmark-mock Benchmark with stub model (no GPU)"
	@echo ""
	@echo "  Inference:"
	@echo "    make serve-ollama  Create Ollama model from merged dir"
	@echo "    make serve-vllm    Serve via vLLM (OpenAI-compatible, GPU)"
	@echo ""
	@echo "  UIs:"
	@echo "    make chat          Gradio chat UI (RAG + sandbox)"
	@echo "    make streamlit     Streamlit chat UI (RAG + sandbox)"
	@echo ""
	@echo "  DevOps:"
	@echo "    make test          Run pytest suite (13 tests)"
	@echo "    make sandbox-build Build isolated Docker sandbox image"
	@echo "    make compose-up    Start sandbox + Streamlit via Docker Compose"
	@echo "    make compose-down  Stop Docker Compose stack"
	@echo "    make clean         Remove generated data/outputs"
	@echo ""
	@echo "  Variables (override with KEY=VALUE):"
	@echo "    MODEL=Qwen/Qwen2.5-Coder-7B-Instruct   (or deepseek-ai/deepseek-coder-6.7b-instruct)"
	@echo "    OUT=outputs/qwen25-coder-7b-cyber"
	@echo "    LLAMA_CPP=/opt/llama.cpp"

venv:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -U pip

deps: venv
	$(VENV)/bin/pip install --quiet torch --index-url https://download.pytorch.org/whl/cpu
	$(VENV)/bin/pip install --quiet -r requirements.txt
	$(VENV)/bin/pip install --quiet pytest streamlit

attack-index:
	$(PYTHON) scripts/attack_map.py --refresh

corpus:
	CVE_LIMIT=150 CWE_LIMIT=80 HF_LIMIT=150 bash scripts/build_corpus.sh

# Full data pipeline: attack index + corpus + HF dataset + LlamaIndex
data: attack-index corpus dataset llama-index

# HF datasets + torch Dataset
dataset: corpus attack-index
	$(VENV)/bin/python scripts/dataset_manager.py --build

# LlamaIndex retrieval
llama-index: dataset
	$(VENV)/bin/python scripts/rag_llama_index.py --build

# PEFT QLoRA fine-tune (run on GPU host: make train CUDA_VISIBLE_DEVICES=0)
train:
	$(VENV)/bin/python scripts/finetune_peft.py --model $(MODEL) --output $(OUT)

eval:
	$(VENV)/bin/python scripts/eval.py --model $(OUT)/merged

sandbox-build:
	docker build -t cyber-llm-sandbox:latest -f docker/Dockerfile.sandbox .

serve-ollama:
	bash scripts/serve_ollama.sh $(OUT)/merged cyber-llm

serve-vllm:
	bash scripts/serve_vllm.sh $(OUT)/merged 8000

chat:
	$(VENV)/bin/python scripts/chat_ui.py --model $(OUT)/merged

streamlit:
	$(VENV)/bin/python -m streamlit run scripts/chat_streamlit.py -- --model $(OUT)/merged

test:
	$(VENV)/bin/python -m pytest tests/ -q

# Unified orchestrator
pipeline:
	$(VENV)/bin/python scripts/pipeline.py $(PIPE_ARGS)

benchmark:
	$(VENV)/bin/python scripts/benchmark.py \
		--models outputs/qwen25-coder-7b-cyber/merged \
		          outputs/deepseek-coder-6.7b-cyber/merged \
		          outputs/llama31-8b-cyber/merged \
		--out outputs/benchmark.json

# No-GPU demo: benchmark the retrieval stub across all 3 model names
benchmark-mock:
	$(VENV)/bin/python scripts/benchmark.py --mock --out outputs/benchmark.json

# No-GPU demo: run the eval harness with the retrieval stub
eval-mock:
	$(VENV)/bin/python scripts/eval.py --mock --out outputs/eval_results.json

# Convert a merged HF model -> quantized GGUF for Ollama (needs llama.cpp)
gguf:
	$(VENV)/bin/python scripts/convert_gguf.py \
		--model $(OUT)/merged --out $(OUT)/gguf \
		--llama-cpp ${LLAMA_CPP:-/opt/llama.cpp} --quant Q4_K_M

# Prove the platform with a REAL tiny model on CPU (no GPU, no training)
demo-real:
	$(VENV)/bin/python scripts/eval.py \
		--model Qwen/Qwen2.5-Coder-0.5B --out outputs/eval_real.json

compose-up: sandbox-build
	docker compose -f docker/docker-compose.full.yml --profile ui --profile sandbox up --build

compose-down:
	docker compose -f docker/docker-compose.full.yml down

install-hooks:
	mkdir -p .git/hooks
	cp .githooks/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed. It will run syntax checks + tests before each commit."

clean:
	rm -rf outputs data/rag data/hf_dataset data/llama_index data/attack/index.json
