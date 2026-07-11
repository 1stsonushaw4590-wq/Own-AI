#!/usr/bin/env python3
"""
Cyber-LLM QLoRA Fine-Tuning Pipeline

Trains Qwen2.5-Coder-7B-Instruct on cybersecurity data using QLoRA (4-bit).
Optimized for RTX 3060 12GB VRAM.

Key design decisions:
- QLoRA: 4-bit NF4 quantization saves VRAM while preserving performance
- LoRA rank 64: balances adaptation quality with memory usage
- Gradient checkpointing: trades compute for memory
- paged_adamw_8bit: reduces optimizer memory by ~50%
- Sequence length 2048: sufficient for security Q&A
"""

import os
import sys
import json
import torch
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq,
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
    PeftModel,
)
from trl import SFTTrainer


MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-Coder-7B-Instruct")
DATASET_PATH = os.getenv("DATASET_PATH", "/data/cyber_train_chat.jsonl")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/outputs")
USE_WANDB = os.getenv("WANDB_API_KEY") is not None

# QLoRA configuration for RTX 3060 12GB
QLORA_CONFIG = {
    "load_in_4bit": True,
    "bnb_4bit_compute_dtype": torch.bfloat16,
    "bnb_4bit_use_double_quant": True,
    "bnb_4bit_quant_type": "nf4",
}

LORA_CONFIG = {
    "r": 64,
    "lora_alpha": 128,
    "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj",
                       "gate_proj", "up_proj", "down_proj"],
    "lora_dropout": 0.05,
    "bias": "none",
    "task_type": "CAUSAL_LM",
}

TRAINING_CONFIG = {
    "output_dir": OUTPUT_DIR,
    "per_device_train_batch_size": 1,
    "gradient_accumulation_steps": 8,
    "num_train_epochs": 3,
    "learning_rate": 2e-4,
    "lr_scheduler_type": "cosine",
    "warmup_ratio": 0.03,
    "logging_steps": 10,
    "save_steps": 500,
    "save_total_limit": 3,
    "bf16": True,
    "tf32": True,
    "gradient_checkpointing": True,
    "gradient_checkpointing_kwargs": {"use_reentrant": False},
    "optim": "paged_adamw_8bit",
    "max_grad_norm": 0.3,
    "report_to": "wandb" if USE_WANDB else "none",
}

MAX_SEQ_LENGTH = 2048


def setup_model_and_tokenizer():
    """Load tokenizer and quantized model."""
    print(f"Loading tokenizer: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_NAME,
        trust_remote_code=True,
        padding_side="right",
    )
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    tokenizer.model_max_length = MAX_SEQ_LENGTH

    print(f"Loading model: {MODEL_NAME} with 4-bit QLoRA")
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

    return tokenizer, model


def apply_lora(model):
    """Apply LoRA adapters to the quantized model."""
    lora_config = LoraConfig(**LORA_CONFIG)
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    return model


def format_chat(example):
    """Format chat messages for training."""
    messages = example["messages"]
    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=False,
    )
    return {"text": text}


def train():
    global tokenizer
    tokenizer, model = setup_model_and_tokenizer()
    model = apply_lora(model)

    print(f"Loading dataset from {DATASET_PATH}")
    dataset = load_dataset("json", data_files=DATASET_PATH, split="train")
    print(f"Dataset size: {len(dataset)} samples")

    dataset = dataset.map(format_chat, remove_columns=dataset.column_names)

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        args=TrainingArguments(**TRAINING_CONFIG),
        train_dataset=dataset,
        max_seq_length=MAX_SEQ_LENGTH,
        dataset_text_field="text",
        packing=False,
    )

    print("Starting training...")
    trainer.train()

    print(f"Saving adapter to {OUTPUT_DIR}/adapter")
    trainer.save_model(f"{OUTPUT_DIR}/adapter")
    tokenizer.save_pretrained(f"{OUTPUT_DIR}/adapter")

    print("Training complete!")

    # Save training config
    config = {
        "base_model": MODEL_NAME,
        "qlora": QLORA_CONFIG,
        "lora": LORA_CONFIG,
        "training": {k: v for k, v in TRAINING_CONFIG.items()
                     if k not in ("report_to",)},
        "max_seq_length": MAX_SEQ_LENGTH,
        "dataset": DATASET_PATH,
    }
    with open(f"{OUTPUT_DIR}/training_config.json", "w") as f:
        json.dump(config, f, indent=2, default=str)
    print(f"Config saved to {OUTPUT_DIR}/training_config.json")


if __name__ == "__main__":
    train()
