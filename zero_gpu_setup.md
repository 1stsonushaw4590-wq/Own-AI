# Hugging Face ZeroGPU Setup for Cyber-LLM Training

## Overview
ZeroGPU provides free GPU time on Hugging Face Spaces:
- **Free tier**: 16 hours/month on T4 (16GB) or A10G (24GB)
- **Pro tier**: More hours with subscription

## Quick Setup

### 1. Create a Space
```bash
# Go to https://huggingface.co/new-space
# Name: cyber-llm-training
# SDK: Docker
# Hardware: ZeroGPU (T4 or A10G)
# Visibility: Private (recommended)
```

### 2. Dockerfile for ZeroGPU
```dockerfile
# Space Dockerfile
FROM python:3.11

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y git curl

# Install Python deps
RUN pip install --no-cache-dir \
    torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121 \
    transformers>=4.47 \
    datasets>=3.3 \
    accelerate>=1.2 \
    peft>=0.14 \
    bitsandbytes>=0.45 \
    trl>=0.14 \
    wandb \
    huggingface_hub

# Clone repo
RUN git clone https://github.com/your-username/cyber-llm.git /app/cyber-llm
WORKDIR /app/cyber-llm

# Set up training script entrypoint
COPY train_zero_gpu.py /app/train_zero_gpu.py
ENTRYPOINT ["python", "/app/train_zero_gpu.py"]
```

### 3. ZeroGPU Training Script (`train_zero_gpu.py`)
```python
#!/usr/bin/env python3
"""
ZeroGPU-optimized training for Cyber-LLM 7B
Optimized for T4 (16GB) / A10G (24GB) with gradient accumulation
"""

import os
import torch
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    TrainingArguments,
    Trainer,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer

# ZeroGPU config
MODEL_NAME = "Qwen/Qwen2.5-Coder-7B-Instruct"
DATASET_PATH = "data/cyber_train_merged.jsonl"  # Upload to Space or HF dataset
OUTPUT_DIR = "/tmp/outputs"  # ZeroGPU ephemeral storage
HF_REPO = "your-username/cyber-llm-7b"  # Push to HF Hub

# QLoRA for T4 (16GB) / A10G (24GB)
QLORA_CONFIG = {
    "load_in_4bit": True,
    "bnb_4bit_compute_dtype": torch.bfloat16,
    "bnb_4bit_use_double_quant": True,
    "bnb_4bit_quant_type": "nf4",
}

LORA_CONFIG = LoraConfig(
    r=64,
    lora_alpha=128,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)

# Optimized for ZeroGPU time limits
TRAINING_CONFIG = TrainingArguments(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=1,
    gradient_accumulation_steps=8,  # Effective batch = 8
    num_train_epochs=1,  # Single epoch for time limit
    max_steps=500,  # Hard limit for ZeroGPU free tier
    learning_rate=2e-4,
    lr_scheduler_type="cosine",
    warmup_ratio=0.03,
    logging_steps=10,
    save_steps=100,
    save_total_limit=2,
    bf16=True,
    tf32=True,
    gradient_checkpointing=True,
    gradient_checkpointing_kwargs={"use_reentrant": False},
    optim="paged_adamw_8bit",
    max_grad_norm=0.3,
    max_seq_length=2048,
    packing=False,
    report_to="wandb" if os.getenv("WANDB_API_KEY") else "none",
    push_to_hub=True,
    hub_model_id=HF_REPO,
    hub_private_repo=True,
)

def main():
    # Login to HF
    from huggingface_hub import login
    if token := os.getenv("HF_TOKEN"):
        login(token=token)
    
    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.model_max_length = 2048

    # Load model with QLoRA
    bnb_config = BitsAndBytesConfig(**QLORA_CONFIG)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=torch.bfloat16,
    )
    model = prepare_model_for_kbit_training(model)
    model.config.use_cache = False
    model = get_peft_model(model, LORA_CONFIG)
    model.print_trainable_parameters()

    # Load dataset
    dataset = load_dataset("json", data_files=DATASET_PATH, split="train")
    print(f"Dataset size: {len(dataset)} samples")

    def format_chat(example):
        messages = example["messages"]
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
        return {"text": text}

    dataset = dataset.map(format_chat, remove_columns=dataset.column_names)

    # Train
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        args=TRAINING_CONFIG,
        train_dataset=dataset,
        max_seq_length=2048,
        dataset_text_field="text",
        packing=False,
    )

    print("Starting ZeroGPU training...")
    trainer.train()

    # Save & push
    trainer.save_model(f"{OUTPUT_DIR}/final")
    tokenizer.save_pretrained(f"{OUTPUT_DIR}/final")
    print("Training complete! Model pushed to HF Hub.")

if __name__ == "__main__":
    main()
```

### 4. Deploy to ZeroGPU
```bash
# Push to your Space
git init
git add .
git commit -m "ZeroGPU training setup"
git remote add origin https://huggingface.co/spaces/your-username/cyber-llm-training
git push origin main
```

### 5. Secrets (Space Settings → Variables)
```
HF_TOKEN=your_hf_token
WANDB_API_KEY=your_wandb_key  # optional
```

## Limitations & Workarounds

| Limitation | Workaround |
|------------|------------|
| 16hr/month free | Use `max_steps=500` (~2-3 hrs) |
| Ephemeral storage | Push checkpoints to HF Hub (`push_to_hub=True`) |
| T4 16GB memory | Use QLoRA 4bit + gradient accumulation 8 |
| Single epoch | Resume from HF Hub checkpoints |

## Alternative: Use HF Inference Endpoints
If training is too slow, use pre-trained models:
- `Qwen/Qwen2.5-Coder-7B-Instruct` (already on HF)
- Fine-tuned variants: `mlabonne/Qwen2.5-Coder-7B-Instruct` etc.

## Local Testing Before Push
```bash
# Test training locally first (CPU)
python3 training/train_cpu.py

# Test with small sample
MAX_SAMPLES=10 NUM_EPOCHS=1 python3 training/train_cpu.py
```
