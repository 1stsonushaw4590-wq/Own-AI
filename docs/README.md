# Cyber-LLM — Fine-tuning toolkit for cybersecurity models

Local dev environment on Kali Linux with Docker sandbox, to fine-tune
**Qwen2.5-Coder**, **DeepSeek-Coder**, and **Llama** into cybersecurity
specialists using **PEFT QLoRA**. Stack: PyTorch + `datasets` (HF) for
data, `peft`/`transformers` Trainer for fine-tuning, **LlamaIndex** for
retrieval (RAG), and **Ollama / vLLM** for local inference. Training runs
on a cloud GPU (RunPod / Lambda / etc.); this box is used for data prep,
retrieval indexing, and safe evaluation of generated code.

## Tech stack
| Concern        | Library / tool                          |
|----------------|-----------------------------------------|
| Dataset mgmt  | Hugging Face `datasets` + torch `Dataset` |
| Fine-tuning    | `peft` (LoRA/QLoRA) + `transformers` Trainer + `bitsandbytes` |
| Retrieval (RAG)| **LlamaIndex** (local embeddings + FAISS) |
| Base models    | Qwen2.5-Coder / DeepSeek-Coder / Llama  |
| Local inference| **Ollama** (local) or **vLLM** (serving) |
| Sandbox        | Docker (network-none, read-only)         |

## Layout
```
configs/        QLoRA hyperparameters + base model configs
docker/         Dockerfile.train, Dockerfile.sandbox, compose file
scripts/        finetune_peft.py, dataset_manager.py, rag_llama_index.py,
                 attack_map.py, scrape_dataset.py, eval.py, chat_ui.py,
                 serve_ollama.sh, serve_vllm.sh, sandbox_run.sh
data/raw/       Your source cybersecurity samples (jsonl)
data/hf_dataset/  Processed HF dataset (Arrow)
data/llama_index/ LlamaIndex vector store
sandbox/        Safe code-exec wrapper
```


## 1. Prepare the dataset
Raw samples go in `data/raw/*.jsonl` as alpaca format:
```json
{"instruction": "...", "input": "...", "output": "..."}
```

### Option A — scrape a public cybersecurity corpus
```bash
pip install requests
# NVD API key avoids 429 rate limits (get one at nvd.nist.gov/developers/request-an-api-key)
export NVD_API_KEY=xxxx
bash scripts/build_corpus.sh        # scrape + merge + validate -> cyber_train.jsonl
```
Sources: NVD CVE API, MITRE CWE, and HuggingFace `secureauth01/cybersecurity-dataset`.
Tune volume with `CVE_LIMIT=300 CWE_LIMIT=150 HF_LIMIT=300 bash scripts/build_corpus.sh`.

### Option B — use only your own samples
```bash
python3 scripts/prep_dataset.py     # -> writes data/processed/cyber_train.jsonl
```

## 2. Build the HF dataset (datasets + torch Dataset)
```bash
python3 scripts/dataset_manager.py --build   # -> data/hf_dataset (Arrow) + ATT&CK tags
```

## 3. Train on a cloud GPU (PEFT QLoRA)
This Kali host has no GPU, so training is pushed to a cloud instance.
```bash
# On the GPU host: install deps, then run PEFT fine-tune
pip install -r requirements.txt
python3 scripts/finetune_peft.py \
    --model Qwen/Qwen2.5-Coder-7B-Instruct \
    --output outputs/qwen25-coder-7b-cyber
# Or use the convenience wrapper (builds docker + remote deploy):
bash scripts/deploy_cloud.sh qwen25-coder
```
Set the base model to one of:
- `Qwen/Qwen2.5-Coder-7B-Instruct` (recommended)
- `deepseek-ai/deepseek-coder-6.7b-instruct`
- `meta-llama/Llama-3.1-8B-Instruct`

The script does 4-bit QLoRA (bitsandbytes NF4) + LoRA via PEFT, trains
with the `transformers` Trainer, saves the **adapter**, and on GPU merges
it into `outputs/.../merged` for deployment.

> You must accept model licenses on Hugging Face and set `HF_TOKEN`:
> Qwen2.5-Coder, DeepSeek-Coder-6.7B, and Llama-3.1-8B-Instruct all
> require gated access / license agreement.

## 3. Run generated code in the sandbox
Never execute model output on the host. Use the isolated container:
```bash
chmod +x scripts/*.sh
./scripts/sandbox_run.sh path/to/generated_script.py
```
The container runs with `--network none`, `--read-only`, dropped caps,
`no-new-privileges`, and memory/CPU limits.

## 4. Merge & serve (on GPU host)
After training, merge the LoRA adapter into the base model:
```bash
axolotl merge_lora configs/qwen25-coder-7b.yaml
```
Then serve with vLLM / llama.cpp / ollama.

## 5. Evaluate the fine-tuned model
CyberSecEval-style harness: checks **benign utility** (answers vuln/remediation
prompts, generated code runs & passes assertions) and **abuse resistance**
(refuses ransomware/DDoS/brute-force prompts, or any produced code is blocked
by the sandbox). Generated code is executed in the Docker sandbox.
```bash
# build the sandbox image once
docker build -t cyber-llm-sandbox:latest -f docker/Dockerfile.sandbox .
# run eval against the merged model
python3 scripts/eval.py --model outputs/qwen25-coder-7b-cyber/merged \
    --out outputs/eval_results.json
```
Report shows e.g. `benign_utility: 3/3 passed`, `abuse_resistance: 3/3 safe`.

## 6. MITRE ATT&CK mapping layer
Index the official ATT&CK Enterprise STIX (Creative Commons) and tag
corpus/model output with technique IDs.
```bash
python3 scripts/attack_map.py --refresh            # download + index (once)
python3 scripts/attack_map.py --search "lateral movement"
python3 scripts/attack_map.py --id T1059           # command & scripting interpreter
python3 scripts/attack_map.py --tag-file data/raw/sample.jsonl  # adds attack_techniques
```
The chat UI uses this index to flag replies referencing sensitive
offensive techniques (T1059, T1110, T1490, T1190, ...) and warns the user
to only run generated code in the sandbox against authorized systems.

## 7. Interactive chat UI (sandbox-backed)
A Gradio chat UI that loads the merged model and lets you run generated
code in the isolated Docker sandbox with a single click. It also flags
sensitive ATT&CK techniques in replies.
```bash
pip install gradio
docker build -t cyber-llm-sandbox:latest -f docker/Dockerfile.sandbox .
python3 scripts/chat_ui.py --model outputs/qwen25-coder-7b-cyber/merged \
    --host 127.0.0.1 --port 7860
# headless / no-Gradio alternative:
python3 scripts/chat_ui.py --model <merged> --no-ui
```
> Run this on the GPU host for usable speed; on the CPU-only Kali box it
> will be very slow.

## 8. RAG with LlamaIndex
Ground the model in your corpus + ATT&CK so it cites real CVE/CWE/technique
data instead of hallucinating. Retrieval is powered by **LlamaIndex**
(local sentence-transformers embeddings + FAISS store, fully offline).

1. Build the index (embeds corpus + 858 ATT&CK techniques):
   ```bash
   python3 scripts/rag_llama_index.py --build   # -> data/llama_index
   ```
2. Inspect retrieved context:
   ```bash
   python3 scripts/rag_llama_index.py --query "How do I remediate CVE-2024-1234?"
   ```
3. The chat UI (`chat_ui.py`) uses LlamaIndex retrieval when the index
   exists: retrieves top-k chunks, builds a grounded prompt (answer only
   from context, cite source id), then generates. Without an index it
   falls back to direct generation.

Index lives in `data/llama_index/`. Rebuild (`--build`) after changing
the corpus or ATT&CK index.

## 9. Local inference — Ollama / vLLM
After merging the adapter (`outputs/.../merged`):

**Ollama** (local, single machine):
```bash
bash scripts/serve_ollama.sh outputs/qwen25-coder-7b-cyber/merged cyber-llm
# then:  ollama run cyber-llm   (or via http://localhost:11434/api/chat)
```

**vLLM** (high-throughput, OpenAI-compatible API, on GPU host):
```bash
bash scripts/serve_vllm.sh outputs/qwen25-coder-7b-cyber/merged 8000
# endpoint: http://localhost:8000/v1/chat/completions
```

## 10. Quick start (Makefile)
```bash
make venv && make deps
make data                                   # attack index + corpus + HF dataset + LlamaIndex
# on the GPU host:
make train MODEL=Qwen/Qwen2.5-Coder-7B-Instruct OUT=outputs/qwen25-coder-7b-cyber
make serve-ollama            # or: make serve-vllm / make chat / make streamlit
```

## 11. Unified pipeline CLI
`scripts/pipeline.py` orchestrates every stage:
```bash
python3 scripts/pipeline.py prepare                       # attack index + corpus + HF dataset
python3 scripts/pipeline.py index                         # LlamaIndex store
python3 scripts/pipeline.py train  --model Qwen/Qwen2.5-Coder-7B-Instruct
python3 scripts/pipeline.py eval   --model outputs/.../merged
python3 scripts/pipeline.py serve  --model outputs/.../merged --backend ollama
```

## 12. Tests
A pytest suite (`tests/test_toolkit.py`) covers dataset build, ATT&CK
lookup/search/tagging, LlamaIndex retrieval, and eval helpers — all
offline (skips gracefully if an index isn't built yet).
```bash
make test          # or: python3 -m pytest tests/ -q
```

## 13. Chat UIs
Two interchangeable front-ends, both RAG-grounded + sandbox-backed:
- **Gradio**: `make chat` (`scripts/chat_ui.py`)
- **Streamlit**: `make streamlit` (`scripts/chat_streamlit.py`)

Both retrieve grounded context from the LlamaIndex store, generate with
the merged model, and let you run generated code in the isolated Docker
sandbox with a single click.

## 14. Multi-model benchmark
Compare Qwen2.5-Coder vs DeepSeek-Coder vs Llama on the eval harness:
```bash
make benchmark
# or explicitly:
python3 scripts/benchmark.py \
    --models outputs/qwen25-coder-7b-cyber/merged \
             outputs/deepseek-coder-6.7b-cyber/merged \
             outputs/llama31-8b-cyber/merged \
    --out outputs/benchmark.json
```
Prints a table of `benign utility` vs `abuse resistance` per model.

## 15. Full Docker stack
`docker/docker-compose.full.yml` brings up the sandbox image + Streamlit UI
(CPU-ok) and an optional vLLM GPU serving profile:
```bash
make compose-up                 # sandbox + Streamlit UI at :8501
make compose-down
# GPU serving (needs nvidia docker):
docker compose -f docker/docker-compose.full.yml --profile serve up --build --gpu
```
GPU training still uses `docker/docker-compose.train.yml` (CUDA + Axolotl).

## 16. CI
GitHub Actions (`.github/workflows/ci.yml`) installs deps in a venv, builds
the ATT&CK + LlamaIndex indexes (skips on no-network), and runs `make test`.

## 17. Run everything on CPU (no GPU) — stub mode
This Kali box has no GPU, so a real merged model can't load. A retrieval-
based **stub model** (`scripts/stub_model.py`) lets the entire pipeline run
locally: RAG retrieval, chat UIs, eval harness, and benchmark. It is NOT a
real LLM — it composes grounded answers from retrieved context — but it
proves the wiring end-to-end.
```bash
make eval-mock            # CyberSecEval-style eval with the stub
make benchmark-mock       # compare 3 model names via the stub
# chat UIs with the stub:
python3 scripts/chat_ui.py --mock --no-ui
streamlit run scripts/chat_streamlit.py -- --mock
```
For real results, train on a GPU host and pass `--model <merged>` instead.



## Hardware notes
- QLoRA (4-bit) lets you fine-tune 7–8B models on a single 24GB GPU
  (e.g. RTX 4090 / A10G / L4). For faster training use 2x A5000+ or A100.
- On this CPU-only Kali box you can run data prep, dataset build, ATT&CK
  tagging and LlamaIndex retrieval, but not the actual GPU training.

## Ethics / legality
This toolkit is for authorized security research, red-team labs, and
defensive tooling. Only run generated exploits in isolated sandboxes
against systems you own or are explicitly authorized to test.
