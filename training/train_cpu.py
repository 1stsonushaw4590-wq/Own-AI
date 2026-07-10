#!/usr/bin/env python3
"""
Cyber-LLM CPU Training Pipeline

Trains Qwen2.5-Coder-0.5B on cybersecurity data using LoRA (no GPU needed).

Design:
  - Uses LoRA (not QLoRA) since bitsandbytes requires CUDA
  - FP32 precision for CPU compatibility
  - Qwen2.5-Coder-0.5B fits in 16GB RAM comfortably
  - 200 samples, 3 epochs as proof of concept
"""

import os
import sys
import json
import torch
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq,
    set_seed,
)
from peft import (
    LoraConfig,
    get_peft_model,
    TaskType,
)

set_seed(42)

MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-Coder-0.5B-Instruct")
DATASET_PATH = os.getenv("DATASET_PATH", "data/cyber_train_chat.jsonl")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs/qwen25-coder-0.5b-cyber")
MAX_SAMPLES = int(os.getenv("MAX_SAMPLES", "176"))
NUM_EPOCHS = int(os.getenv("NUM_EPOCHS", "3"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "1"))
GRADIENT_ACCUMULATION_STEPS = int(os.getenv("GRADIENT_ACCUMULATION_STEPS", "4"))
LEARNING_RATE = float(os.getenv("LEARNING_RATE", "5e-4"))
MAX_SEQ_LENGTH = int(os.getenv("MAX_SEQ_LENGTH", "512"))

LORA_CONFIG = {
    "r": 16,
    "lora_alpha": 32,
    "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj"],
    "lora_dropout": 0.05,
    "bias": "none",
    "task_type": TaskType.CAUSAL_LM,
}


def setup():
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Device: {device}")

    if not os.path.exists(DATASET_PATH):
        print(f"Dataset not found. Run: python3 dataset/build_dataset.py")
        sys.exit(1)

    print(f"Loading tokenizer: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.model_max_length = MAX_SEQ_LENGTH

    print(f"Loading model: {MODEL_NAME}")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float32,
        trust_remote_code=True,
    )
    model.config.use_cache = False
    model = model.to(device)

    print("Applying LoRA...")
    lora_config = LoraConfig(**LORA_CONFIG)
    model = get_peft_model(model, lora_config)

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    print(f"Trainable parameters: {trainable:,} ({100 * trainable / total:.2f}%)")
    print(f"Total parameters: {total:,}")

    return tokenizer, model


def load_and_prepare_dataset(tokenizer):
    print(f"Loading dataset from {DATASET_PATH}")
    dataset = load_dataset("json", data_files=DATASET_PATH, split="train")

    if len(dataset) > MAX_SAMPLES:
        print(f"Limiting to {MAX_SAMPLES} samples (from {len(dataset)})")
        dataset = dataset.select(range(MAX_SAMPLES))

    print(f"Dataset size: {len(dataset)} samples")

    def format_chat(example):
        messages = example["messages"]
        text = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=False,
        )
        return {"text": text}

    dataset = dataset.map(format_chat, remove_columns=dataset.column_names)

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
    )

    dataset = dataset.train_test_split(test_size=0.05, seed=42)
    return dataset["train"], dataset["test"]


def train():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    tokenizer, model = setup()
    train_dataset, eval_dataset = load_and_prepare_dataset(tokenizer)

    data_collator = DataCollatorForSeq2Seq(
        tokenizer=tokenizer,
        model=model,
        padding=True,
        label_pad_token_id=-100,
    )

    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=GRADIENT_ACCUMULATION_STEPS,
        num_train_epochs=NUM_EPOCHS,
        learning_rate=LEARNING_RATE,
        lr_scheduler_type="cosine",
        warmup_steps=10,
        logging_steps=5,
        save_steps=50,
        save_total_limit=2,
        eval_strategy="steps",
        eval_steps=50,
        fp16=False,
        bf16=False,
        dataloader_pin_memory=False,
        report_to="none",
        optim="adamw_torch",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        processing_class=tokenizer,
        data_collator=data_collator,
    )

    print("Starting training...")
    print(f"  Model: {MODEL_NAME}")
    print(f"  Output: {OUTPUT_DIR}")
    print(f"  Epochs: {NUM_EPOCHS}")
    print(f"  Batch size: {BATCH_SIZE}")
    print(f"  Max seq length: {MAX_SEQ_LENGTH}")

    trainer.train()

    print(f"Saving model to {OUTPUT_DIR}")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    adapter_path = os.path.join(OUTPUT_DIR, "adapter")
    os.makedirs(adapter_path, exist_ok=True)
    model.save_pretrained(adapter_path)
    tokenizer.save_pretrained(adapter_path)
    print(f"Adapter saved to {adapter_path}")

    config = {
        "base_model": MODEL_NAME,
        "lora": LORA_CONFIG,
        "training": {
            "num_epochs": NUM_EPOCHS,
            "batch_size": BATCH_SIZE,
            "gradient_accumulation_steps": GRADIENT_ACCUMULATION_STEPS,
            "learning_rate": LEARNING_RATE,
            "max_seq_length": MAX_SEQ_LENGTH,
            "max_samples": MAX_SAMPLES,
            "dataset": DATASET_PATH,
            "device": "cpu",
        },
    }
    with open(os.path.join(OUTPUT_DIR, "training_config.json"), "w") as f:
        json.dump(config, f, indent=2, default=str)

    print(f"\nTraining complete! Model saved to {OUTPUT_DIR}")
    print(f"To merge adapter: python3 training/merge_cpu.py --adapter {adapter_path}")
    print(f"To chat: python3 scripts/chat_ui.py --model {OUTPUT_DIR}")


if __name__ == "__main__":
    train()
