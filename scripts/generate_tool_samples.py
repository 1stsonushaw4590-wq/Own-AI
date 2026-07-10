#!/usr/bin/env python3
"""Generate dataset samples by running real Kali tools in the Docker sandbox.

Executes security tools (nmap, sqlmap, hydra, etc.) against controlled
targets in the sandbox and formats their output as instruction samples.
This produces realistic, grounded training data with actual tool output.

Usage:
    python3 scripts/generate_tool_samples.py [--sandbox-url http://localhost:8002]
"""

import json
import os
import sys
import urllib.request
import urllib.error

SANDBOX_URL = os.environ.get("SANDBOX_URL", "http://localhost:8002")
OUTPUT_PATH = os.environ.get("OUTPUT_PATH", "data/tool_samples.jsonl")


def sandbox_run(code, lang="bash", timeout=30):
    """Run code in the Docker sandbox via HTTP API."""
    payload = json.dumps({"code": code, "lang": lang}).encode()
    req = urllib.request.Request(
        SANDBOX_URL, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=timeout)
    return json.loads(resp.read())


def generate_nmap_sample():
    """Scan the Docker gateway with nmap and create a training sample."""
    print("  Running nmap scan on gateway...")
    result = sandbox_run("nmap -sn 172.17.0.1 2>&1; echo '====='; nmap -sV --top-ports 10 172.17.0.1 2>&1", lang="bash")
    output = result.get("stdout", "") + result.get("stderr", "")
    return {
        "instruction": "Run an nmap service version scan on localhost and explain the results.",
        "output": f"## Nmap Scan Results (127.0.0.1)\n\n```\n{output.strip()}\n```\n\n### Analysis\n"
                  f"The scan completed with exit code {result.get('returncode')}. "
                  "Nmap detected open ports and their service versions. "
                  "This technique (T1046 - Network Service Scanning) is used for network enumeration during reconnaissance.",
        "source": "kali_nmap",
        "domain": "network_security",
    }


def generate_sqlmap_sample():
    """Run sqlmap help and create a training sample."""
    print("  Running sqlmap help...")
    result = sandbox_run("sqlmap --help 2>&1 | head -40")
    output = result.get("stdout", "") + result.get("stderr", "")
    return {
        "instruction": "Explain how sqlmap detects and exploits SQL injection vulnerabilities, with example usage.",
        "output": f"## SQLMap SQL Injection Detection\n\n"
                  f"sqlmap ({output.split(chr(10))[0].strip()}) is an automated SQL injection tool.\n\n"
                  "### Key Capabilities\n"
                  "- Detects SQL injection in GET/POST parameters, headers, cookies\n"
                  "- Supports: Boolean, Time, Error, UNION, Stacked queries\n"
                  "- Can enumerate databases, tables, columns\n"
                  "- Can dump data and spawn interactive shells\n\n"
                  "### Example Usage\n"
                  "```bash\n"
                  "# Basic detection\n"
                  "sqlmap -u 'http://target.com/page?id=1' --batch\n\n"
                  "# Enumerate databases\n"
                  "sqlmap -u 'http://target.com/page?id=1' --dbs\n\n"
                  "# Dump table\n"
                  "sqlmap -u 'http://target.com/page?id=1' -D dbname -T users --dump\n```\n\n"
                  "### Detection Techniques\n"
                  "1. **Boolean blind**: Injects conditions and compares response content\n"
                  "2. **Time-based**: Uses SLEEP/BENCHMARK to detect delays\n"
                  "3. **Error-based**: Triggers SQL errors that leak information\n"
                  "4. **UNION query**: Extracts data via UNION SELECT statements\n\n"
                  "### Mitigation\n"
                  "- Use parameterized queries / prepared statements\n"
                  "- Input validation and whitelisting\n"
                  "- WAF rules to block suspicious SQL patterns",
        "source": "kali_sqlmap",
        "domain": "application_security",
    }


def generate_hydra_sample():
    """Run hydra help and create a training sample about brute force."""
    print("  Running hydra...")
    result = sandbox_run("hydra -h 2>&1 | head -20")
    output = result.get("stdout", "") + result.get("stderr", "")
    return {
        "instruction": "Describe how Hydra performs brute-force password attacks and how to defend against them.",
        "output": f"## Hydra Password Brute-Forcing\n\n"
                  f"```\n{output.strip()}\n```\n\n"
                  "### Attack Mechanics\n"
                  "Hydra supports brute-forcing: FTP, SSH, HTTP(S), MySQL, PostgreSQL, SMB, RDP, and more.\n\n"
                  "### Example Commands\n"
                  "```bash\n"
                  "# SSH brute force with user list\n"
                  "hydra -L users.txt -P pass.txt ssh://target.com\n\n"
                  "# HTTP POST form brute force\n"
                  "hydra -l admin -P pass.txt target.com http-post-form \\\n"
                  "  '/login:user=^USER^&pass=^PASS^:F=incorrect'\n```\n\n"
                  "### Defenses\n"
                  "- Account lockout after N failed attempts\n"
                  "- Rate limiting per IP\n"
                  "- SSH key auth instead of passwords\n"
                  "- Fail2ban or similar IPS\n"
                  "- MFA (multi-factor authentication)",
        "source": "kali_hydra",
        "domain": "offensive_security",
    }


def generate_john_sample():
    """Run john and create a password cracking sample."""
    print("  Running john...")
    result = sandbox_run("john --help 2>&1 | head -15")
    output = result.get("stdout", "") + result.get("stderr", "")
    return {
        "instruction": "How does John the Ripper crack password hashes and what are best practices for password storage?",
        "output": f"## John the Ripper Password Cracking\n\n"
                  f"{output.strip()}\n\n"
                  "### Supported Formats\n"
                  "- Unix DES/MD5/BSDi, SHA-256/512\n"
                  "- Windows LM/NT\n"
                  "- macOS salted SHA-512\n"
                  "- MySQL, PostgreSQL, Oracle\n"
                  "- PDF, ZIP, RAR archives\n\n"
                  "### Cracking Modes\n"
                  "1. **Wordlist**: `john --wordlist=rockyou.txt hash.txt`\n"
                  "2. **Incremental** (brute force): `john --incremental hash.txt`\n"
                  "3. **Rules-based**: Appends/prepends word mutations\n"
                  "4. **Mask attack**: `--mask=?l?l?l?d?d`\n\n"
                  "### Password Storage Best Practices\n"
                  "- Use **bcrypt**, **scrypt**, or **Argon2id**\n"
                  "- Salt every password (unique per user)\n"
                  "- Work factor >= 10 (bcrypt) / >= 2 (Argon2id)\n"
                  "- Never use MD5, SHA-1, or unsalted SHA-256 for passwords",
        "source": "kali_john",
        "domain": "offensive_security",
    }


def generate_nikto_sample():
    """Run nikto and create a web scanner sample."""
    print("  Running nikto...")
    result = sandbox_run("nikto -Version 2>&1")
    output = result.get("stdout", "") + result.get("stderr", "")
    return {
        "instruction": "What is Nikto and how is it used for web server vulnerability scanning?",
        "output": f"## Nikto Web Server Scanner\n\n"
                  f"{output.strip()}\n\n"
                  "### Overview\n"
                  "Nikto is an open-source web server scanner that tests for:\n"
                  "- Outdated server software\n"
                  "- Dangerous files/CGIs\n"
                  "- Misconfigurations\n"
                  "- Default files and programs\n"
                  "- Information disclosure\n\n"
                  "### Example Usage\n"
                  "```bash\n"
                  "# Basic scan\n"
                  "nikto -h http://target.com\n\n"
                  "# Scan on specific port with SSL\n"
                  "nikto -h https://target.com -p 443\n\n"
                  "# Save output\n"
                  "nikto -h http://target.com -o report.html\n```\n\n"
                  "### Limitations\n"
                  "- No authentication support\n"
                  "- Can generate false positives\n"
                  "- Complimentary to DAST tools like Burp Suite, ZAP",
        "source": "kali_nikto",
        "domain": "application_security",
    }


def generate_dirb_sample():
    """Run dirb and create a directory enumeration sample."""
    print("  Running dirb...")
    result = sandbox_run("dirb --help 2>&1 | head -20")
    output = result.get("stdout", "") + result.get("stderr", "")
    return {
        "instruction": "How does directory brute-forcing work in web application security testing?",
        "output": f"## Directory Brute-Forcing\n\n"
                  f"{output.strip()}\n\n"
                  "### How It Works\n"
                  "Directory busting tools (dirb, gobuster, ffuf) send HTTP requests\n"
                  "using a wordlist of common paths and analyze HTTP status codes:\n"
                  "- **200 OK** - Found\n"
                  "- **301/302** - Redirect (often interesting)\n"
                  "- **403** - Forbidden (exists but restricted)\n"
                  "- **404** - Not found\n\n"
                  "### Example\n"
                  "```bash\n"
                  "dirb http://target.com /usr/share/dirb/wordlists/common.txt\n"
                  "```\n\n"
                  "### Defenses\n"
                  "- Rate limiting\n"
                  "- WAF detection of rapid sequential requests\n"
                  "- Obfuscate admin panel paths (non-standard names)\n"
                  "- `.htaccess` / Nginx auth on admin paths",
        "source": "kali_dirb",
        "domain": "application_security",
    }


SAMPLES = [
    ("Nmap", generate_nmap_sample),
    ("SQLMap", generate_sqlmap_sample),
    ("Hydra", generate_hydra_sample),
    ("John", generate_john_sample),
    ("Nikto", generate_nikto_sample),
    ("Dirb", generate_dirb_sample),
]


def main():
    os.makedirs(os.path.dirname(OUTPUT_PATH) or ".", exist_ok=True)

    existing = set()
    if os.path.exists(OUTPUT_PATH):
        with open(OUTPUT_PATH) as f:
            for line in f:
                s = json.loads(line)
                existing.add(s.get("source"))

    samples = []
    for name, gen_fn in SAMPLES:
        if gen_fn.__name__ in existing:
            print(f"Skipping {name} (already generated)")
            continue
        print(f"Generating {name} sample...")
        try:
            sample = gen_fn()
            samples.append(sample)
            print(f"  -> {name} OK")
        except Exception as e:
            print(f"  -> {name} FAILED: {e}")

    if samples:
        with open(OUTPUT_PATH, "a") as f:
            for s in samples:
                f.write(json.dumps(s) + "\n")
        print(f"\nSaved {len(samples)} samples to {OUTPUT_PATH}")
    else:
        print("No new samples generated.")

    # Also build the dataset with these new samples
    print("\nRebuilding main dataset with new tool samples...")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dataset"))
    from build_dataset import main as build_main
    try:
        build_main()
    except SystemExit:
        pass


if __name__ == "__main__":
    main()
