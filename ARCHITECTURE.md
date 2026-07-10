# Cyber Security Foundation Model — Architecture

## Overview

Microservices-based platform for building, serving, and interacting with a
cybersecurity-specialized LLM. All components run in Docker.

## Base Model: Qwen2.5-Coder-7B-Instruct

Selected for:
- Best code generation benchmarks (85.5% HumanEval)
- Strong instruction following
- 32K context window
- Active maintenance by Alibaba Cloud
- Permissive license (Apache 2.0)
- Fits RTX 3060 12GB with QLoRA 4-bit (~6GB VRAM)

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        Traefik (SSL/TLS)                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │  React   │  │  FastAPI │  │  vLLM    │  │  Qdrant    │  │
│  │  UI      │◄─┤  API     │◄─┤ Inference│  │  VectorDB  │  │
│  │  :3000   │  │  :8000   │  │  :8001   │  │  :6333     │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────────┘  │
│       │              │             │                         │
│  ┌────┴─────┐  ┌────┴─────┐  ┌────┴─────┐  ┌────────────┐  │
│  │  MinIO   │  │PostgreSQL│  │  Redis   │  │  Celery    │  │
│  │  :9000   │  │  :5432   │  │  :6379   │  │  Worker    │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────────┘  │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐  │
│  │  Docker  │  │ Training │  │  Monitoring              │  │
│  │  Sandbox │  │  Axolotl │  │  Prometheus + Grafana    │  │
│  └──────────┘  └──────────┘  └──────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Service Breakdown

| Service | Tech | Port | Purpose |
|---|---|---|---|
| Frontend | Next.js 14 | 3000 | Web UI for chat, code review, analysis |
| API | FastAPI | 8000 | REST API, auth, rate limiting |
| Inference | vLLM | 8001 | OpenAI-compatible LLM serving |
| VectorDB | Qdrant | 6333 | RAG vector storage |
| Database | PostgreSQL | 5432 | User data, sessions, audit logs |
| Cache | Redis | 6379 | Session cache, task queue |
| Storage | MinIO | 9000 | Dataset storage, model artifacts |
| Worker | Celery | — | Async tasks (training, eval) |
| Sandbox | Docker | — | Isolated code execution |
| Monitor | Prometheus+Grafana | 9090/3001 | Metrics & dashboards |

## Data Flow

1. User sends prompt via Web UI → API Gateway
2. API optionally retrieves RAG context from Qdrant
3. Prompt + context sent to vLLM inference
4. Response returned to UI
5. Code blocks can be executed in Docker sandbox
6. All interactions logged to PostgreSQL + Prometheus

## Dataset

Balanced cybersecurity instruction dataset with **150 training samples** across **22 security domains** and **28 sources**.

| Domain | Samples | Source |
|---|---|---|
| Threat Intelligence (ATT&CK) | 100 | MITRE ATT&CK v15.1 |
| Application Security | 11 | OWASP, secure coding guidelines |
| Offensive Security | 5 | Pentest methodology, exploitation |
| Cloud Security | 4 | AWS/Azure/GCP hardening |
| Network Security | 3 | Network protocols, monitoring |
| Defensive Security | 3 | Blue team operations |
| Incident Response | 3 | SANS IR framework |
| Malware Analysis | 2 | Static/dynamic analysis |
| Reverse Engineering | 2 | Binary analysis |
| Detection Engineering | 2 | Sigma rules, KQL |
| Kubernetes Security | 2 | Pod security, RBAC |
| AI Security | 2 | Prompt injection, LLM risks |
| Governance/Risk/Compliance | 2 | GDPR, NIST CSF |
| Docker Security | 1 | Container hardening |
| Windows AD | 1 | Kerberos, Active Directory |
| Linux Security | 1 | OS hardening |
| Threat Hunting | 1 | KQL queries |
| Digital Forensics | 1 | NTFS, USB artifacts |
| DevSecOps | 1 | CI/CD pipeline security |
| Identity/Access Management | 1 | OAuth, IAM |
| Threat Intelligence | 1 | Threat intel lifecycle |
| Security Leadership | 1 | Security ROI, metrics |

ATT&CK techniques sampled at 100 from 858 total to prevent domain imbalance.

## Training Pipeline

1. Dataset generation (`dataset/build_dataset.py`) → ATT&CK sampling + 22 domain expert content
2. QLoRA 4-bit fine-tuning via PEFT/TRL (GPU) or vanilla LoRA (CPU proof of concept)
3. Adapter merging with base model
4. GGUF quantization (Q4_K_M) via llama.cpp
5. Model served via Ollama or vLLM

## Model Checkpoints

| Model | Size | Parameters | Status |
|---|---|---|---|
| Qwen2.5-Coder-0.5B-Instruct (LoRA) | CPU/0.5B | 2.1M trainable (0.44%) | ✅ Trained, merged |
| Qwen2.5-Coder-7B-Instruct (QLoRA) | RTX 3060 / Colab T4 | ~80M trainable | 🔜 Planned |

## Security

- All code execution in isolated Docker sandboxes
  - `--network none`, `--read-only`, `--cap-drop ALL`
  - Memory/CPU limits, non-root user
  - Auto-cleanup after execution
- API authentication via API keys + JWT
- Rate limiting per user/IP
- Audit logging for all prompts/responses
- Network isolation between services
