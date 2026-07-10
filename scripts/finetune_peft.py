#!/usr/bin/env python3
"""QLoRA fine-tuning with PEFT + transformers Trainer.

Fine-tunes a base model (Qwen2.5-Coder / DeepSeek-Coder / Llama) using
4-bit quantization (bitsandbytes) + LoRA adapters (PEFT). Trains on the
HF dataset built by dataset_manager.py. Runs on a single GPU (24GB+).

Usage:
  python3 scripts/finetune_peft.py \
      --model Qwen/Qwen2.5-Coder-7B-Instruct \
      --output outputs/qwen25-coder-7b-cyber
"""
import argparse
import os

import torch
from datasets import load_from_disk
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments,
    BitsAndBytesConfig,
)
from peft import LoraConfig, prepare_model_for_kbit_training, get_peft_model


def build_prompt(ex):
    """Alpaca-style prompt formatting."""
    if ex.get("input"):
        return (
            f"### Instruction:\n{ex['instruction']}\n\n"
            f"### Input:\n{ex['input']}\n\n### Response:\n{ex['output']}"
        )
    return f"### Instruction:\n{ex['instruction']}\n\n### Response:\n{ex['output']}"


def tokenize(ex, tokenizer, max_len):
    text = build_prompt(ex)
    out = tokenizer(text, truncation=True, max_length=max_len)
    out["labels"] = out["input_ids"].copy()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    ap.add_argument("--output", default="outputs/cyber-model")
    ap.add_argument("--dataset", default="data/hf_dataset")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch", type=int, default=2)
    ap.add_argument("--grad-accum", type=int, default=4)
    ap.add_argument("--max-len", type=int, default=4096)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--lora-r", type=int, default=64)
    ap.add_argument("--lora-alpha", type=int, default=128)
    ap.add_argument("--no-cuda", action="store_true")
    args = ap.parse_args()

    device = "cpu" if (args.no_cuda or not torch.cuda.is_available()) else "cuda"
    print(f"Device: {device} | Model: {args.model}")

    bnb = BitsAndBytesConfig(
        load_in_4bit=True, bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        args.model, quantization_config=bnb, device_map="auto",
        trust_remote_code=True,
    )
    model = prepare_model_for_kbit_training(model)

    lora = LoraConfig(
        r=args.lora_r, lora_alpha=args.lora_alpha, lora_dropout=0.05,
        bias="none", task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    raw = load_from_disk(args.dataset)
    ds = raw["train"] if isinstance(raw, dict) else raw
    tok_ds = ds.map(lambda e: tokenize(e, tokenizer, args.max_len),
                    remove_columns=ds.column_names, batched=False)

    training_args = TrainingArguments(
        output_dir=args.output, per_device_train_batch_size=args.batch,
        gradient_accumulation_steps=args.grad_accum, num_train_epochs=args.epochs,
        learning_rate=args.lr, lr_scheduler_type="cosine", warmup_ratio=0.03,
        bf16=(device == "cuda"), fp16=False, gradient_checkpointing=True,
        logging_steps=10, save_strategy="epoch", optim="adamw_torch",
        report_to="none", max_grad_norm=0.3,
    )

    trainer = Trainer(model=model, args=training_args, train_dataset=tok_ds)
    trainer.train()

    # Save adapter only
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)
    print(f"LoRA adapter saved -> {args.output}")

    # Optional: merge for deployment
    if device == "cuda":
        print("Merging adapter into base weights for deployment...")
        merged = model.merge_and_unload()
        merged.save_pretrained(args.output + "/merged")
        tokenizer.save_pretrained(args.output + "/merged")
        print(f"Merged model -> {args.output}/merged")


if __name__ == "__main__":
    main()
