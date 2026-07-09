# Cyber-LLM

Fine-tuning toolkit for cybersecurity language models. Train **Qwen2.5-Coder**, **DeepSeek-Coder**, and **Llama** into cybersecurity specialists using LoRA/QLoRA, retrieve grounded context with LlamaIndex, and serve locally via Ollama/vLLM — all with Docker-sandboxed code execution.

## Quick start

```bash
git clone <this-repo> && cd cyber-llm
make venv && make deps
make data          # ATT&CK index + corpus + HF dataset + LlamaIndex
make test          # run pytest suite (13 tests)
make help          # show all 20+ targets
```

## Tech stack

| Concern | Tool |
|---|---|
| Dataset | HuggingFace `datasets` + torch `Dataset` |
| Fine-tune | `peft` QLoRA + `transformers` Trainer + `bitsandbytes` |
| Retrieval | **LlamaIndex** (offline, FAISS + bge) |
| Base models | Qwen2.5-Coder / DeepSeek-Coder / Llama |
| Serving | **Ollama** (local) / **vLLM** (GPU) |
| UIs | Gradio + Streamlit (RAG-grounded, sandbox-backed) |
| Safety | Docker sandbox (`--network none`, `--read-only`) |
| CI | GitHub Actions |

## Project status

```
make pipeline status    # or: python3 scripts/pipeline.py status
```

## Docs

Full documentation (19 sections): [docs/README.md](docs/README.md)

## License

MIT
