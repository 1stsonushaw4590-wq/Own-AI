#!/usr/bin/env python3
"""Merge enhanced dataset with existing training data"""

import json
from pathlib import Path

def convert_to_chat_format(input_file, output_file):
    """Convert instruction/response format to chat format"""
    with open(input_file) as f_in, open(output_file, 'w') as f_out:
        for line in f_in:
            sample = json.loads(line)
            chat_sample = {
                "messages": [
                    {"role": "user", "content": sample["instruction"]},
                    {"role": "assistant", "content": sample["output"]}
                ],
                "source": sample.get("source", "enhanced"),
                "domain": sample.get("domain", "general")
            }
            f_out.write(json.dumps(chat_sample) + '\n')

def merge_datasets():
    # Convert enhanced dataset
    convert_to_chat_format(
        "/home/areeb/Desktop/cyber-llm/data/enhanced/enhanced_cyber_dataset.jsonl",
        "/home/areeb/Desktop/cyber-llm/data/enhanced/enhanced_chat.jsonl"
    )
    
    # Merge with existing
    with open("/home/areeb/Desktop/cyber-llm/data/cyber_train_chat.jsonl") as f1:
        existing = [json.loads(line) for line in f1]
    
    with open("/home/areeb/Desktop/cyber-llm/data/enhanced/enhanced_chat.jsonl") as f2:
        enhanced = [json.loads(line) for line in f2]
    
    merged = existing + enhanced
    
    with open("/home/areeb/Desktop/cyber-llm/data/cyber_train_merged.jsonl", 'w') as f_out:
        for sample in merged:
            f_out.write(json.dumps(sample) + '\n')
    
    print(f"Existing: {len(existing)}, Enhanced: {len(enhanced)}, Merged: {len(merged)}")

if __name__ == "__main__":
    merge_datasets()