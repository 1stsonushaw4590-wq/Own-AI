#!/usr/bin/env python3
"""
Cyber-LLM 7B QLoRA GPU Training Pipeline

Trains Qwen2.5-Coder-7B-Instruct on cybersecurity data using QLoRA (4-bit).
Optimized for RTX 3090/4090 (24GB) or A10G/A100.

Requirements:
- GPU with 24GB+ VRAM (RTX 3090/4090, A10G, A100)
- CUDA 12.1+
- bitsandbytes, peft, trl, accelerate

Usage:
    DATASET_PATH=data/cyber_train_merged.jsonl \
    MODEL_NAME=Qwen/Qwen2.5-Coder-7B-Instruct \
    OUTPUT_DIR=outputs/qwen25-coder-7b-cyber \
    python3 training/train_7b_gpu.py

Environment Variables:
    DATASET_PATH      - Path to training JSONL (default: data/cyber_train_merged.jsonl)
    MODEL_NAME        - Base model (default: Qwen/Qwen2.5-Coder-7B-Instruct)
    OUTPUT_DIR        - Output directory (default: outputs/qwen25-coder-7b-cyber)
    MAX_SAMPLES       - Max training samples (default: all)
    NUM_EPOCHS        - Training epochs (default: 3)
    BATCH_SIZE        - Batch size (default: 1)
    GRAD_ACCUM        - Gradient accumulation (default: 8)
    LEARNING_RATE     - LR (default: 2e-4)
    MAX_SEQ_LENGTH    - Sequence length (default: 2048)
    USE_WANDB         - Enable wandb (default: false)
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
    set_seed,
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
    PeftModel,
)
from trl import SFTTrainer


set_seed(42)

# =======================
# CONFIGURATION
# =======================
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-Coder-7B-Instruct")
DATASET_PATH = os.getenv("DATASET_PATH", "data/cyber_train_merged.jsonl")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs/qwen25-coder-7b-cyber")
MAX_SAMPLES = int(os.getenv("MAX_SAMPLES", "0"))  # 0 = all
NUM_EPOCHS = int(os.getenv("NUM_EPOCHS", "3"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "1"))
GRAD_ACCUM = int(os.getenv("GRAD_ACCUM", "8"))
LEARNING_RATE = float(os.getenv("LEARNING_RATE", "2e-4"))
MAX_SEQ_LENGTH = int(os.getenv("MAX_SEQ_LENGTH", "2048"))
USE_WANDB = os.getenv("USE_WANDB", "false").lower() == "true"

# QLoRA 4-bit config for 7B on 24GB VRAM
QLORA_CONFIG = {
    "load_in_4bit": True,
    "bnb_4bit_compute_dtype": torch.bfloat16,
    "bnb_4bit_use_double_quant": True,
    "bnb_4bit_quant_type": "nf4",
}

LORA_CONFIG = {
    "r": 64,
    "lora_alpha": 128,
    "target_modules": [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ],
    "lora_dropout": 0.05,
    "bias": "none",
    "task_type": "CAUSAL_LM",
}

TRAINING_CONFIG = {
    "output_dir": OUTPUT_DIR,
    "per_device_train_batch_size": BATCH_SIZE,
    "gradient_accumulation_steps": GRAD_ACCUM,
    "num_train_epochs": NUM_EPOCHS,
    "learning_rate": LEARNING_RATE,
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
    "max_seq_length": MAX_SEQ_LENGTH,
    "packing": False,
    "report_to": "wandb" if USE_WANDB else "none",
    "dataloader_pin_memory": False,
    "dataloader_num_workers": 2,
}


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
    model.config.pretraining_tp = 1

    return tokenizer, model


def apply_lora(model):
    """Apply LoRA adapters to the quantized model."""
    print("Applying LoRA adapters...")
    lora_config = LoraConfig(**LORA_CONFIG)
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    return model


def format_chat(example):
    """Convert instruction/output or messages to chat format."""
    if "messages" in example:
        messages = example["messages"]
    elif "instruction" in example and "output" in example:
        messages = [
            {"role": "user", "content": example["instruction"]},
            {"role": "assistant", "content": example["output"]}
        ]
    else:
        keys = list(example.keys())
        if len(keys) >= 2:
            messages = [
                {"role": "user", "content": str(example[keys[0]])},
                {"role": "assistant", "content": str(example[keys[1]])}
            ]
        else:
            messages = [{"role": "user", "content": str(example)}]

    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=False,
    )
    return {"text": text}


def load_and_prepare_dataset(tokenizer):
    """Load and tokenize the training dataset."""
    global tokenizer
    tokenizer = tokenizer  # Make tokenizer available for format_chat

    print(f"Loading dataset from {DATASET_PATH}")
    dataset = load_dataset("json", data_files=DATASET_PATH, split="train")

    if MAX_SAMPLES > 0 and len(dataset) > MAX_SAMPLES:
        print(f"Limiting to {MAX_SAMPLES} samples (from {len(dataset)})")
        dataset = dataset.select(range(MAX_SAMPLES))

    print(f"Dataset size: {len(dataset)} samples")

    def format_chat(example):
        if "messages" in example:
            messages = example["messages"]
        elif "instruction" in example and "output" in example:
            messages = [
                {"role": "user", "content": example["instruction"]},
                {"role": "assistant", "content": example["output"]}
            ]
        else:
            keys = list(example.keys())
            if len(keys) >= 2:
                messages = [
                    {"role": "user", "content": str(example[keys[0]])},
                    {"role": "assistant", "content": str(example[keys[1]])}
                ]
            else:
                messages = [{"role": "user", "content": str(example)}]

        text = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=False,
        )
        return {"text": text}

    dataset = dataset.map(format_chat, remove_columns=dataset.column_names)
    print(f"Formatted {len(dataset)} samples")

    def tokenize_fn(examples):
        tok = tokenizer(
            examples["text"],
            truncation=True,
            padding="max_length",
            max_length=MAX_SEQ_LENGTH,
        )
        tok["labels"] = tok["input_ids"].copy()
        return tok

    dataset = dataset.map(
        tokenize_fn,
        batched=True,
        remove_columns=["text"],
        num_proc=4,
    )

    dataset = dataset.train_test_split(test_size=0.02, seed=42)
    print(f"Train: {len(dataset['train'])}, Eval: {len(dataset['test'])}")
    return dataset["train"], dataset["test"]


def train():
    """Main training function."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    global tokenizer
    tokenizer, model = setup_model_and_tokenizer()
    model = apply_lora(model)

    train_dataset, eval_dataset = load_and_prepare_dataset(tokenizer)

    data_collator = DataCollatorForSeq2Seq(
        tokenizer=tokenizer,
        model=model,
        padding=True,
        label_pad_token_id=-100,
    )

    training_args = TrainingArguments(**TRAINING_CONFIG)

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        max_seq_length=MAX_SEQ_LENGTH,
        dataset_text_field="text",
        data_collator=data_collator,
        packing=False,
    )

    print("Starting training...")
    print(f"  Model: {MODEL_NAME}")
    print(f"  Output: {OUTPUT_DIR}")
    print(f"  Epochs: {NUM_EPOCHS}")
    print(f"  Batch size: {BATCH_SIZE} (grad accum: {GRAD_ACCUM})")
    print(f"  LR: {LEARNING_RATE}")
    print(f"  Max seq len: {MAX_SEQ_LENGTH}")

    trainer.train()

    print(f"\nSaving adapter to {OUTPUT_DIR}/adapter")
    trainer.save_model(f"{OUTPUT_DIR}/adapter")
    tokenizer.save_pretrained(f"{OUTPUT_DIR}/adapter")

    # Save training config
    config = {
        "base_model": MODEL_NAME,
        "qlora": QLORA_CONFIG,
        "lora": LORA_CONFIG,
        "training": {k: v for k, v in TRAINING_CONFIG.items()
                     if k not in ("report_to",)},
        "dataset": DATASET_PATH,
        "max_samples": MAX_SAMPLES,
        "max_seq_length": MAX_SEQ_LENGTH,
    }
    with open(f"{OUTPUT_DIR}/training_config.json", "w") as f:
        json.dump(config, f, indent=2, default=str)

    print(f"\n✅ Training complete! Adapter saved to {OUTPUT_DIR}/adapter")
    print(f"Next: python3 training/merge_and_quantize.py \\")
    print(f"  --base {MODEL_NAME} \\")
    print(f"  --adapter {OUTPUT_DIR}/adapter \\")
    print(f"  --output {OUTPUT_DIR}/merged \\")
    print(f"  --gguf {OUTPUT_DIR}/gguf")


if __name__ == "__main__":
    train()