"""Quick inference test across diverse cybersecurity domains"""
import torch, json, sys, os, re, random
from transformers import AutoModelForCausalLM, AutoTokenizer

model_path = sys.argv[1] if len(sys.argv) > 1 else "outputs/qwen25-coder-0.5b-cyber/merged"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 6

device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Loading model from {model_path} on {device}...")
tok = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained(model_path, trust_remote_code=True, torch_dtype=torch.float32)
model.to(device)
model.eval()

prompts = [
    ("OT Security", "Write a Snort rule to detect a KEP server replay attack against a PLC using port 502."),
    ("Forensics", "What artifacts would you examine on a Windows 10 system to determine when a USB device was last connected?"),
    ("Bug Bounty", "How do I exploit a subdomain takeover where acme-staging.example.com has a CNAME pointing to a deleted CloudFront distribution?"),
    ("Network Security", "Explain how BGP hijacking works and how RPKI prevents it."),
    ("Secure Coding", "Fix this Python code for SQL injection vulnerability:\n```\ndef get_user(user_id):\n    cur.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n    return cur.fetchone()\n```"),
    ("Threat Hunting", "Write a KQL query to detect suspicious scheduled task creation in the last 7 days."),
    ("AI Security", "What is prompt injection and how can I defend against it in my LLM application?"),
    ("GDPR/Compliance", "What are the key requirements for a Data Processing Agreement under GDPR?"),
    ("DevSecOps", "Write a Dockerfile best practice that avoids running as root."),
    ("IAM", "What is the difference between OAuth 2.0 authorization code flow and implicit flow? Which is safer?"),
    ("Cloud Security", "List the top 5 misconfigurations in AWS S3 buckets that lead to data breaches."),
    ("Reverse Engineering", "What is the difference between static and dynamic analysis in malware reverse engineering?"),
    ("K8s Security", "Write a Kubernetes Pod Security Policy that prevents privileged containers."),
    ("Detection Engineering", "Write a Sigma rule to detect Mimikatz usage."),
    ("Linux Security", "Harden an Ubuntu 24.04 server for production: list the top 10 essential steps."),
    ("Threat Intel", "Describe the typical TTPs of a ransomware group like LockBit."),
    ("Incident Response", "What are the 6 phases of the SANS incident response process?"),
    ("Digital Forensics", "How do you recover deleted files from an NTFS volume?"),
    ("Identity Security", "Explain how Active Directory Kerberos authentication works step by step."),
    ("Security Leadership", "How do you calculate and present cybersecurity ROI to the board of directors?"),
]

for i, (domain, prompt) in enumerate(prompts[:n]):
    messages = [{"role": "user", "content": prompt}]
    text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tok(text, return_tensors="pt", truncation=True, max_length=512).to(device)
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=200, temperature=0.3, do_sample=True, pad_token_id=tok.pad_token_id or tok.eos_token_id)
    response = tok.decode(out[0][inputs.input_ids.shape[1]:], skip_special_tokens=True).strip()
    print(f"\n{'='*60}")
    print(f"[{domain}] Q: {prompt[:80]}...")
    print(f"A: {response[:200]}")
