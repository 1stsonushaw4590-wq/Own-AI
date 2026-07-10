# Cyber-LLM toolkit — Makefile
PYTHON ?= python3
VENV   ?= .venv
MODEL  ?= Qwen/Qwen2.5-Coder-7B-Instruct
OUT    ?= outputs/qwen25-coder-0.5b-cyber
LLAMA_CPP ?= /opt/llama.cpp
COMPOSE_FLAGS ?= --profile cpu

.PHONY: help setup deps attack-index corpus dataset llama-index train eval \
        sandbox-build serve-ollama serve-vllm chat streamlit test pipeline \
        benchmark benchmark-mock eval-mock gguf demo-real compose-up \
        compose-down clean install-hooks status docker-up docker-down \
        docker-build api-build frontend-build dataset-build training-build \
        train-docker merge quantize

help:
	@echo "Cyber-LLM — Cyber Security Foundation Model"
	@echo ""
	@echo "=== Setup ==="
	@echo "  make setup          Full setup: venv + deps + data pipeline"
	@echo "  make venv           Create Python virtualenv"
	@echo "  make deps           Install Python dependencies"
	@echo ""
	@echo "=== Data Pipeline ==="
	@echo "  make data           Full: attack index + corpus + HF dataset + LlamaIndex"
	@echo "  make attack-index   MITRE ATT&CK index (858 techniques)"
	@echo "  make corpus         Scrape NVD CVE / CWE / HF dataset"
	@echo "  make dataset        Build HF dataset from corpus"
	@echo "  make llama-index    Build LlamaIndex retrieval store"
	@echo ""
	@echo "=== Training (GPU host) ==="
	@echo "  make train          QLoRA fine-tune (set MODEL=... OUT=...)"
	@echo "  make train-docker   Train inside Docker container"
	@echo "  make merge          Merge LoRA adapter with base model"
	@echo "  make quantize       Quantize merged model to GGUF Q4_K_M"
	@echo "  make gguf           Full: merge + quantize (needs llama.cpp)"
	@echo ""
	@echo "=== Docker Services ==="
	@echo "  make docker-up      Start all Docker services"
	@echo "  make docker-down    Stop all Docker services"
	@echo "  make docker-build   Build all Docker images"
	@echo "  make api            Start API + DB + Redis + Qdrant"
	@echo "  make frontend       Start frontend dev server"
	@echo "  make inference      Start vLLM inference (GPU)"
	@echo "  make monitoring     Start Prometheus + Grafana"
	@echo ""
	@echo "=== Evaluation ==="
	@echo "  make eval           Eval merged model"
	@echo "  make eval-mock      Eval with stub model (no GPU)"
	@echo "  make demo-real      Eval with Qwen2.5-Coder-0.5B on CPU"
	@echo "  make benchmark      Benchmark all models"
	@echo "  make benchmark-mock Benchmark with stub"
	@echo ""
	@echo "=== UIs ==="
	@echo "  make chat           Gradio chat UI (stub mode)"
	@echo "  make streamlit      Streamlit chat UI (stub mode)"
	@echo "  make chat-ui        Launch Next.js frontend"
	@echo ""
	@echo "=== DevOps ==="
	@echo "  make test           Run pytest suite"
	@echo "  make sandbox-build  Build Docker sandbox image"
	@echo "  make status         Show project status"
	@echo "  make clean          Remove generated data/outputs"
	@echo ""
	@echo "=== Variables ==="
	@echo "  MODEL=Qwen/Qwen2.5-Coder-7B-Instruct"
	@echo "  OUT=outputs/qwen25-coder-7b-cyber"

# ─── Setup ──────────────────────────────────────────────────

setup: venv deps data
	@echo "Setup complete."

venv:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -U pip

deps: venv
	$(VENV)/bin/pip install --quiet torch --index-url https://download.pytorch.org/whl/cpu
	$(VENV)/bin/pip install --quiet -r requirements.txt
	$(VENV)/bin/pip install --quiet pytest streamlit

# ─── Data Pipeline ─────────────────────────────────────────

attack-index:
	$(PYTHON) scripts/attack_map.py --refresh

corpus:
	CVE_LIMIT=150 CWE_LIMIT=80 HF_LIMIT=150 bash scripts/build_corpus.sh

data: attack-index corpus dataset llama-index

dataset: corpus attack-index
	$(VENV)/bin/python scripts/dataset_manager.py --build

llama-index: dataset
	$(VENV)/bin/python scripts/rag_llama_index.py --build

# ─── Training ──────────────────────────────────────────────

train:
	$(VENV)/bin/python scripts/finetune_peft.py --model $(MODEL) --output $(OUT)

# CPU training with Qwen2.5-Coder-0.5B (proof of concept, no GPU needed)
train-cpu:
	$(VENV)/bin/python training/train_cpu.py

# Train on Colab (opens notebook)
train-colab:
	@echo "Open the Colab notebook at:"
	@echo "  training/colab_train.ipynb"
	@echo ""
	@echo "Or upload to Google Colab directly:"
	@echo "  1. Go to https://colab.research.google.com"
	@echo "  2. Upload training/colab_train.ipynb"
	@echo "  3. Runtime -> Change runtime type -> T4 GPU"
	@echo "  4. Run all cells"

train-docker:
	docker compose run --rm training \
		python3 train.py

merge:
	$(VENV)/bin/python training/merge_and_quantize.py \
		--base $(MODEL) --adapter $(OUT)/adapter \
		--output $(OUT)/merged --skip-gguf

# Merge CPU-trained model (0.5B)
merge-cpu:
	$(VENV)/bin/python training/merge_cpu.py

quantize:
	$(VENV)/bin/python training/merge_and_quantize.py \
		--base $(MODEL) --adapter $(OUT)/adapter \
		--output $(OUT)/merged --gguf $(OUT)/gguf \
		--llama-cpp $(LLAMA_CPP)

gguf:
	$(VENV)/bin/python scripts/convert_gguf.py \
		--model $(OUT)/merged --out $(OUT)/gguf \
		--llama-cpp $(LLAMA_CPP) --quant Q4_K_M

# ─── Docker Services ───────────────────────────────────────

docker-build:
	docker compose build

docker-up:
	docker compose $(COMPOSE_FLAGS) up -d

docker-down:
	docker compose down

api:
	docker compose up -d postgres redis qdrant api

frontend:
	cd frontend && npm install && npm run dev

inference:
	docker compose --profile gpu up -d inference

monitoring:
	docker compose --profile monitoring up -d prometheus grafana

sandbox-build:
	sg docker -c "docker build -t cyber-llm-sandbox:latest -f docker/Dockerfile.sandbox ."

# ─── Evaluation ────────────────────────────────────────────

eval:
	$(VENV)/bin/python scripts/eval.py --model $(OUT)/merged

eval-mock:
	$(VENV)/bin/python scripts/eval.py --mock --out outputs/eval_results.json

demo-real:
	$(VENV)/bin/python scripts/eval.py \
		--model Qwen/Qwen2.5-Coder-0.5B --out outputs/eval_real.json

benchmark:
	$(VENV)/bin/python scripts/benchmark.py \
		--models outputs/qwen25-coder-7b-cyber/merged \
		          outputs/deepseek-coder-6.7b-cyber/merged \
		          outputs/llama31-8b-cyber/merged \
		--out outputs/benchmark.json

benchmark-mock:
	$(VENV)/bin/python scripts/benchmark.py --mock --out outputs/benchmark.json

# ─── UIs ───────────────────────────────────────────────────

chat:
	$(VENV)/bin/python scripts/chat_ui.py --mock --host 0.0.0.0 --port 7860

streamlit:
	$(VENV)/bin/python -m streamlit run scripts/chat_streamlit.py -- --mock

chat-ui:
	$(VENV)/bin/python scripts/chat_ui.py --mock --host 0.0.0.0 --port 7860

# ─── Testing ───────────────────────────────────────────────

test:
	$(VENV)/bin/python -m pytest tests/ -q

# ─── Utilities ─────────────────────────────────────────────

status:
	$(VENV)/bin/python scripts/pipeline.py status

clean:
	rm -rf outputs data/rag data/hf_dataset data/llama_index data/attack/index.json

install-hooks:
	mkdir -p .git/hooks
	cp .githooks/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed."

# ─── Unified pipeline ──────────────────────────────────────

pipeline:
	$(VENV)/bin/python scripts/pipeline.py $(PIPE_ARGS)
