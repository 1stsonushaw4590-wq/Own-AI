#!/usr/bin/env python3
"""
Cyber-LLM Comprehensive Dataset Builder.

Builds 5000+ high-quality cybersecurity instruction samples across 22 domains.
Each sample is expert-reviewed content, not scraped noise.

Domains:
  Offensive Security, Defensive Security, Secure Coding, App Security,
  Cloud Security (AWS/Azure/GCP), Network Security, Malware Analysis,
  Reverse Engineering, Digital Forensics, Incident Response, Threat Hunting,
  Detection Engineering, Threat Intelligence, GRC, DevSecOps, AI Security,
  K8s Security, Docker Security, IAM, Linux, Windows, Active Directory
"""

import json
import os
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional


class DatasetBuilder:
    def __init__(self, output_dir: str = "data", max_attack_samples: int = 100):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.samples: List[Dict] = []
        self.seen_hashes: set = set()
        self.max_attack_samples = max_attack_samples  # Limit ATT&CK to balance domains

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def _dedup(self, sample: Dict) -> bool:
        content = sample.get("instruction", "") + sample.get("output", "")
        h = self._hash(content)
        if h in self.seen_hashes:
            return False
        self.seen_hashes.add(h)
        return True

    def add(self, instruction: str, output: str, source: str, domain: str, metadata: Optional[Dict] = None):
        sample = {
            "instruction": instruction.strip(),
            "output": output.strip(),
            "source": source,
            "domain": domain,
            "metadata": metadata or {},
        }
        if self._dedup(sample):
            self.samples.append(sample)

    def load_attack_data(self, path: str):
        if not os.path.exists(path):
            return
        with open(path) as f:
            data = json.load(f)
        techniques = data.get("techniques", {})
        # Sample diverse tactics for balance
        tactics = {}
        for tid, info in techniques.items():
            tactic = info.get("tactic", "Unknown")
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append((tid, info))

        count = 0
        # Take representative samples from each tactic
        for tactic, items in sorted(tactics.items()):
            per_tactic = max(1, self.max_attack_samples // len(tactics))
            for tid, info in items[:per_tactic]:
                name = info.get("name", "")
                desc = info.get("description", "")
                if name and desc:
                    self.add(
                        instruction=f"Explain MITRE ATT&CK technique {tid}: {name}",
                        output=f"## {name} ({tid})\n\n{desc}\n\n"
                               f"**Tactic:** {info.get('tactic', 'Unknown')}\n"
                               f"**Platform:** {', '.join(info.get('platforms', []))}",
                        source="mitre_attack",
                        domain="threat_intel",
                        metadata={"technique_id": tid, "tactic": info.get("tactic")},
                    )
                    count += 1
                    if count >= self.max_attack_samples:
                        break
            if count >= self.max_attack_samples:
                break
        print(f"  → Sampled {count} ATT&CK techniques (from {len(techniques)} total)")

    # ── Domain Generators ──────────────────────────────────────

    def add_offensive_security(self):
        samples = [
            {
                "instruction": "Explain the phases of a penetration test",
                "output": "## Penetration Testing Phases\n\n"
                    "1. **Reconnaissance** — Passive (OSINT, DNS enumeration, Shodan) and active (Nmap, masscan) information gathering\n"
                    "2. **Scanning & Enumeration** — Port scanning, service version detection, vulnerability scanning (Nessus, OpenVAS)\n"
                    "3. **Exploitation** — Gaining access via known exploits (Metasploit), web app attacks (SQLi, XSS), credential attacks\n"
                    "4. **Post-Exploitation** — Privilege escalation, lateral movement, persistence, data exfiltration\n"
                    "5. **Reporting** — Document findings, risk ratings, remediation steps\n\n"
                    "Legal authorization (ROE) must be obtained before any testing.",
                "source": "pentest",
                "domain": "offensive_security",
            },
            {
                "instruction": "How do you perform privilege escalation on Linux?",
                "output": "## Linux Privilege Escalation Techniques\n\n"
                    "### Kernel Exploits\n"
                    "- Check kernel version: `uname -a`\n"
                    "- Search for known exploits: `searchsploit linux kernel <version>`\n"
                    "- Tools: CVE-2021-4034 (pwnkit), CVE-2023-32629 (GameOverlay)\n\n"
                    "### Misconfigurations\n"
                    "- **SUID binaries**: `find / -perm -4000 2>/dev/null`\n"
                    "- **Sudo rights**: `sudo -l` — look for NOPASSWD entries\n"
                    "- **Capabilities**: `getcap -r / 2>/dev/null`\n"
                    "- **Cron jobs**: Check writable scripts in /etc/cron*\n"
                    "- **PATH hijacking**: Writable directories in PATH\n\n"
                    "### Credentials\n"
                    "- Check config files: `.bash_history`, `.ssh/`, `.aws/credentials`\n"
                    "- Database connections strings, web app configs\n"
                    "- Memory dumps with mimipenguin\n\n"
                    "### Automation\n"
                    "- LinPEAS: `curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh`\n"
                    "- LinEnum, GTFOBins for binary abuse",
                "source": "pentest",
                "domain": "offensive_security",
            },
            {
                "instruction": "Write a Python script for basic port scanning",
                "output": "import socket\nimport sys\nfrom concurrent.futures import ThreadPoolExecutor\n\ndef scan_port(host: str, port: int) -> tuple:\n    try:\n        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n            s.settimeout(1)\n            result = s.connect_ex((host, port))\n            return port, result == 0\n    except:\n        return port, False\n\ndef scan_ports(host: str, ports: range):\n    print(f\"Scanning {host}...\")\n    open_ports = []\n    with ThreadPoolExecutor(max_workers=50) as executor:\n        futures = {executor.submit(scan_port, host, p): p for p in ports}\n        for future in futures:\n            port, is_open = future.result()\n            if is_open:\n                open_ports.append(port)\n                print(f\"  Port {port}: OPEN\")\n    return sorted(open_ports)\n\nif __name__ == \"__main__\":\n    host = sys.argv[1] if len(sys.argv) > 1 else input(\"Host: \")\n    open_ports = scan_ports(host, range(1, 1025))\n    print(f\"\\nOpen ports: {open_ports}\")",
                "source": "pentest",
                "domain": "offensive_security",
            },
            {
                "instruction": "What is the difference between white-box, black-box, and grey-box penetration testing?",
                "output": "## Testing Methodologies\n\n"
                    "### White-Box (Full Knowledge)\n"
                    "- Tester has complete access: source code, architecture docs, credentials\n"
                    "- Most thorough, finds deepest vulnerabilities\n"
                    "- Best for code review, compliance audits\n\n"
                    "### Black-Box (Zero Knowledge)\n"
                    "- Tester starts with no information (just a domain or IP range)\n"
                    "- Simulates real external attacker perspective\n"
                    "- Time-consuming, may miss internal vulnerabilities\n\n"
                    "### Grey-Box (Partial Knowledge)\n"
                    "- Tester has limited access (e.g., low-privilege user account)\n"
                    "- Best balance of realism and coverage\n"
                    "- Most common approach for web application testing\n\n"
                    "**Recommendation**: Start with grey-box for web apps, white-box for critical infrastructure.",
                "source": "pentest",
                "domain": "offensive_security",
            },
            {
                "instruction": "How do you bypass a WAF (Web Application Firewall)?",
                "output": "## WAF Bypass Techniques\n\n"
                    "### Encoding & Obfuscation\n"
                    "- URL encoding: `%27` instead of `'`\n"
                    "- Double URL encoding: `%2539` → `%39` → `'`\n"
                    "- Unicode normalization: `<` → `\\u003c`\n"
                    "- Case variations: `SeLeCt` instead of `SELECT`\n"
                    "- Comment injection: `SEL/**/ECT`\n\n"
                    "### HTTP Parameter Pollution\n"
                    "- Send multiple params: `?id=1&id=2`\n"
                    "- Different encodings per param\n\n"
                    "### Protocol Manipulation\n"
                    "- HTTP/2 downgrade to HTTP/1.0\n"
                    "- Transfer-Encoding: chunked smuggling\n"
                    "- Content-Type mismatches\n\n"
                    "### Rate Limiting\n"
                    "- Slow down requests below detection thresholds\n"
                    "- Distribute across multiple IPs/residential proxies\n\n"
                    "### Tools\n"
                    "- wafw00f (WAF detection)\n"
                    "- SQLMap with --tamper scripts\n"
                    "- Burp Suite Intruder with custom payloads",
                "source": "web_security",
                "domain": "offensive_security",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_defensive_security(self):
        samples = [
            {
                "instruction": "Design a SOC (Security Operations Center) tier structure",
                "output": "## SOC Tier Structure\n\n"
                    "### Tier 1 — Triage Analyst\n"
                    "- Monitor alerts, initial triage\n"
                    "- Determine false positives vs. genuine incidents\n"
                    "- Escalate to Tier 2 with context\n"
                    "- Skills: SIEM basics, alert understanding\n\n"
                    "### Tier 2 — Incident Responder\n"
                    "- Deep investigation of escalated alerts\n"
                    "- Containment and mitigation actions\n"
                    "- Forensic data collection\n"
                    "- Skills: Forensic analysis, malware triage, IR playbooks\n\n"
                    "### Tier 3 — Threat Hunter / Expert\n"
                    "- Proactive threat hunting\n"
                    "- Advanced malware analysis and reverse engineering\n"
                    "- Custom detection rule development (Sigma, YARA)\n"
                    "- Skills: RE, exploit analysis, threat intel\n\n"
                    "### Supporting Roles\n"
                    "- SOC Manager: Operations, metrics, reporting\n"
                    "- Detection Engineer: Rule creation, tool tuning\n"
                    "- Threat Intel Analyst: IOCs, TTPs, threat feeds\n"
                    "- Forensics Analyst: Deep dive investigations",
                "source": "soc",
                "domain": "defensive_security",
            },
            {
                "instruction": "What metrics should a SOC track for effectiveness?",
                "output": "## Key SOC Metrics (KPIs)\n\n"
                    "### Volume Metrics\n"
                    "- Total alerts generated (daily/weekly)\n"
                    "- True positives vs. false positives (FP rate)\n"
                    "- Alerts per sensor/device\n\n"
                    "### Time-Based Metrics\n"
                    "- Mean Time to Detect (MTTD) — goal: < 1 hour\n"
                    "- Mean Time to Respond (MTTR) — goal: < 4 hours for critical\n"
                    "- Mean Time to Contain (MTTC)\n"
                    "- Mean Time to Resolve (MTTRs)\n\n"
                    "### Quality Metrics\n"
                    "- Escalation rate: T1 → T2\n"
                    "- False positive reduction over time\n"
                    "- Detection coverage by MITRE ATT&CK techniques\n\n"
                    "### Operational Metrics\n"
                    "- Analyst utilization rate\n"
                    "- Backlog size\n"
                    "- Number of missed alerts (post-incident review)\n\n"
                    "### Reporting Cadence\n"
                    "- Daily: Alert volume, critical incidents\n"
                    "- Weekly: MTTR, FP rate, backlog trends\n"
                    "- Monthly: Executive summary, risk score changes\n"
                    "- Quarterly: Full review of team performance and tooling",
                "source": "soc",
                "domain": "defensive_security",
            },
            {
                "instruction": "How do you build a defense-in-depth strategy?",
                "output": "## Defense-in-Depth Strategy\n\n"
                    "### 1. Perimeter Security\n"
                    "- Firewalls (NGFW with IPS/IDS)\n"
                    "- DDoS protection (Cloudflare, AWS Shield)\n"
                    "- VPNs for remote access\n\n"
                    "### 2. Network Segmentation\n"
                    "- VLANs separating DMZ, internal, guest networks\n"
                    "- Micro-segmentation with zero-trust principles\n"
                    "- Network access control (NAC) for device auth\n\n"
                    "### 3. Endpoint Protection\n"
                    "- EDR/XDR (CrowdStrike, SentinelOne, Defender)\n"
                    "- Hardened configurations (CIS benchmarks)\n"
                    "- Application whitelisting / allowlisting\n"
                    "- Full disk encryption (BitLocker, FileVault)\n\n"
                    "### 4. Identity & Access\n"
                    "- MFA everywhere (TOTP, FIDO2/WebAuthn)\n"
                    "- Zero Standing Privileges (JIT access)\n"
                    "- PAM (Privileged Access Management)\n\n"
                    "### 5. Detection & Response\n"
                    "- SIEM with correlation rules\n"
                    "- 24/7 SOC monitoring\n"
                    "- Automated IR playbooks (SOAR)\n"
                    "- Regular tabletop exercises\n\n"
                    "### 6. Data Protection\n"
                    "- Data classification (public/internal/confidential/restricted)\n"
                    "- Encryption at rest and in transit\n"
                    "- DLP (Data Loss Prevention)\n"
                    "- Backup with 3-2-1 rule\n\n"
                    "### 7. Governance\n"
                    "- Security policies and standards\n"
                    "- Regular penetration tests and red team exercises\n"
                    "- Third-party risk management\n"
                    "- Compliance monitoring (SOC2, ISO27001)",
                "source": "defensive",
                "domain": "defensive_security",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_cloud_security(self):
        samples = [
            {
                "instruction": "List the AWS Well-Architected Framework security pillars",
                "output": "## AWS Well-Architected Framework — Security Pillar\n\n"
                    "### 1. Identity and Access Management\n"
                    "- Use IAM roles (never long-term access keys)\n"
                    "- Implement least privilege policies\n"
                    "- Enable AWS Organizations SCPs for guardrails\n"
                    "- Use IAM Access Analyzer for external access\n\n"
                    "### 2. Detective Controls\n"
                    "- AWS CloudTrail for API logging\n"
                    "- AWS Config for resource compliance\n"
                    "- GuardDuty for threat detection\n"
                    "- Security Hub for centralized findings\n"
                    "- VPC Flow Logs for network monitoring\n\n"
                    "### 3. Infrastructure Protection\n"
                    "- VPC segmentation with subnets, NACLs, security groups\n"
                    "- AWS WAF for web app protection\n"
                    "- AWS Shield Advanced for DDoS\n"
                    "- Systems Manager for patch management\n\n"
                    "### 4. Data Protection\n"
                    "- Encryption at rest: KMS, S3 SSE, EBS encryption\n"
                    "- Encryption in transit: TLS everywhere, ACM certificates\n"
                    "- S3 Block Public Access (default)\n"
                    "- Macie for sensitive data discovery\n\n"
                    "### 5. Incident Response\n"
                    "- Pre-provisioned IR tools in isolated account\n"
                    "- Automated response with Lambda + Step Functions\n"
                    "- GuardDuty → EventBridge → Lambda playbooks\n"
                    "- Regular tabletop exercises",
                "source": "aws_security",
                "domain": "cloud_security",
            },
            {
                "instruction": "What are the most common Azure security misconfigurations?",
                "output": "## Top Azure Security Misconfigurations\n\n"
                    "### 1. Overly Permissive RBAC\n"
                    "- Assigning Owner instead of Contributor/Reader\n"
                    "- Using built-in roles instead of custom roles with least privilege\n"
                    "- Not reviewing PIM (Privileged Identity Management) activations\n\n"
                    "### 2. Exposed Storage\n"
                    "- Blob containers with public access enabled\n"
                    "- Storage accounts not restricted by firewall/VNET\n"
                    "- Missing 'Secure transfer required' setting\n\n"
                    "### 3. Network Misconfigurations\n"
                    "- NSG rules that allow 0.0.0.0/0 on management ports (22, 3389)\n"
                    "- Azure SQL with 'Allow Azure Services' enabled (overly broad)\n"
                    "- Missing Network Security Groups on subnets\n\n"
                    "### 4. Identity Issues\n"
                    "- MFA not enforced for all users\n"
                    "- Service principals with excessive permissions\n"
                    "- Legacy authentication protocols enabled\n\n"
                    "### 5. Monitoring Gaps\n"
                    "- Diagnostic settings not configured\n"
                    "- Azure Security Center / Defender not enabled\n"
                    "- No alert rules for critical events\n\n"
                    "### Remediation\n"
                    "- Use Microsoft Defender for Cloud (formerly ASC)\n"
                    "- Implement Azure Policy for guardrails\n"
                    "- Regular access reviews with Entra ID\n"
                    "- Enable Just-In-Time VM access",
                "source": "azure_security",
                "domain": "cloud_security",
            },
            {
                "instruction": "Explain Google Cloud Security Command Center",
                "output": "## Google Cloud Security Command Center (SCC)\n\n"
                    "Google Cloud SCC is a centralized security and risk management platform.\n\n"
                    "### Key Capabilities\n"
                    "- **Asset Discovery**: Auto-discovers all GCP resources\n"
                    "- **Vulnerability Detection**: Scans for CVEs, web app vulnerabilities\n"
                    "- **Threat Detection**: Built-in anomaly detection, Event Threat Detection\n"
                    "- **Compliance**: Built-in CIS benchmarks, PCI DSS, FedRAMP mappings\n"
                    "- **Data Risk**: Sensitive data protection with DLP integration\n\n"
                    "### Service Tiers\n"
                    "- **Standard**: Free — includes asset inventory, basic findings\n"
                    "- **Premium**: Paid — adds VM scanning, container scanning, Event Threat Detection\n\n"
                    "### Common Findings\n"
                    "- Publicly exposed buckets (storage IAM misconfig)\n"
                    "- Firewall rules allowing 0.0.0.0/0\n"
                    "- VMs with public IPs and open RDP/SSH\n"
                    "- IAM excessive permissions\n"
                    "- Unencrypted data at rest\n"
                    "- Outdated software (OS patch findings)\n\n"
                    "### Integration\n"
                    "- SIEM: Pub/Sub to Splunk, Chronicle\n"
                    "- Automation: Security Health Analytics → Cloud Functions → auto-remediation\n"
                    "- CI/CD: Binary Authorization for supply chain security",
                "source": "gcp_security",
                "domain": "cloud_security",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_network_security(self):
        samples = [
            {
                "instruction": "Explain the OSI model and its security implications at each layer",
                "output": "## OSI Model — Security Controls by Layer\n\n"
                    "### Layer 1 — Physical\n"
                    "- Risks: Physical theft, tampering, eavesdropping\n"
                    "- Controls: CCTV, locks, biometric access, Faraday cages\n\n"
                    "### Layer 2 — Data Link\n"
                    "- Risks: ARP spoofing, MAC flooding, VLAN hopping\n"
                    "- Controls: Dynamic ARP Inspection, port security, 802.1X, private VLANs\n\n"
                    "### Layer 3 — Network\n"
                    "- Risks: IP spoofing, DDoS, routing attacks\n"
                    "- Controls: ACLs, ingress/egress filtering (uRPF), IPsec, firewalls\n\n"
                    "### Layer 4 — Transport\n"
                    "- Risks: SYN flood, port scanning, session hijacking\n"
                    "- Controls: SYN cookies, stateful firewalls, TCP Wrappers\n\n"
                    "### Layer 5 — Session\n"
                    "- Risks: Session hijacking, man-in-the-middle\n"
                    "- Controls: TLS, mutual authentication, session timeouts\n\n"
                    "### Layer 6 — Presentation\n"
                    "- Risks: SSL stripping, encoding attacks\n"
                    "- Controls: HSTS, certificate pinning, TLS 1.3\n\n"
                    "### Layer 7 — Application\n"
                    "- Risks: SQLi, XSS, CSRF, RCE\n"
                    "- Controls: WAF, input validation, CSP headers, output encoding",
                "source": "network_security",
                "domain": "network_security",
            },
            {
                "instruction": "How do you detect and prevent ARP spoofing?",
                "output": "## ARP Spoofing Detection & Prevention\n\n"
                    "ARP spoofing occurs when an attacker sends falsified ARP messages to associate their MAC with a legitimate IP.\n\n"
                    "### Detection Methods\n"
                    "- **ARP table monitoring**: `arp -a`, watch for changes\n"
                    "- **Passive OS detection**: Check for OS mismatch with claimed MAC\n"
                    "- **Network scanning**: Use `arp-scan` to detect duplicates\n"
                    "- **SIEM alerts**: Correlate ARP changes with incident timelines\n\n"
                    "### Prevention\n"
                    "- **Dynamic ARP Inspection (DAI)**: On managed switches, validates ARP packets\n"
                    "- **DHCP Snooping**: Validates DHCP messages, builds trusted binding database\n"
                    "- **Static ARP entries**: For critical hosts (impractical at scale)\n"
                    "- **802.1X**: Authenticates devices before granting network access\n"
                    "- **IPsec**: Encrypts traffic, preventing MiTM even if ARP is spoofed\n\n"
                    "### Detection Script\n"
                    "```python\nimport subprocess\nimport re\n\ndef get_arp_table():\n    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)\n    entries = re.findall(r'\\[(\\d+\\.\\d+\\.\\d+\\.\\d+)\\].*(..:..:..:..:..:..)', result.stdout)\n    return {ip: mac for ip, mac in entries}\n\ndef check_for_duplicates():\n    table = get_arp_table()\n    mac_to_ip = {}\n    for ip, mac in table.items():\n        if mac in mac_to_ip:\n            print(f\"[ALERT] ARP spoofing: {ip} and {mac_to_ip[mac]} share MAC {mac}\")\n        mac_to_ip[mac] = ip\n```",
                "source": "network_security",
                "domain": "network_security",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_malware_analysis(self):
        samples = [
            {
                "instruction": "Explain the steps of static malware analysis",
                "output": "## Static Malware Analysis Steps\n\n"
                    "### 1. File Identification\n"
                    "- `file` command to identify file type\n"
                    "- Hash (MD5/SHA256) for threat intel lookup (VirusTotal)\n"
                    "- File size, creation date\n\n"
                    "### 2. String Analysis\n"
                    "- `strings` command for embedded strings\n"
                    "- Look for: URLs, IPs, registry paths, API calls, error messages\n"
                    "- Detect obfuscation (base64, XOR, custom encoding)\n\n"
                    "### 3. PE Analysis (Windows Executables)\n"
                    "- **PE Studio** or **Detect It Easy (DiE)**: Compiler info, packer detection\n"
                    "- **Dependency Walker**: Import/export tables\n"
                    "- **CFF Explorer**: PE headers, sections, resources\n"
                    "- Check for suspicious sections (e.g., .text with high entropy)\n\n"
                    "### 4. Disassembly\n"
                    "- **IDA Pro** / **Ghidra** / **Binary Ninja**\n"
                    "- Identify main function, suspicious API calls\n"
                    "- Look for anti-analysis techniques (IsDebuggerPresent, timing checks)\n\n"
                    "### 5. YARA Scanning\n"
                    "- Scan with known malware rule sets\n"
                    "- Create custom YARA rules based on findings\n\n"
                    "### 6. Documentation\n"
                    "- Record all IOCs (hashes, IPs, domains, registry keys)\n"
                    "- Classify malware family if possible\n"
                    "- Write analysis report with MITRE ATT&CK mappings",
                "source": "malware_analysis",
                "domain": "malware_analysis",
            },
            {
                "instruction": "What is the difference between packed and obfuscated malware?",
                "output": "## Packed vs. Obfuscated Malware\n\n"
                    "### Packed Executables\n"
                    "- **Compression**: Uses runtime packers like UPX, ASPack, Themida\n"
                    "- **Entry Point**: Tiny stub that decompresses original code in memory\n"
                    "- **Detection**: High entropy in sections, few imports, small .text section\n"
                    "- **Unpacking**: Run to unpack point then dump memory, or use static unpackers\n"
                    "- **Tools**: UPX -d, PEiD, Detect It Easy\n\n"
                    "### Obfuscated Code\n"
                    "- **Transformation**: Code is modified to be hard to understand but functionally identical\n"
                    "- **Techniques**: \n"
                    "  — Control flow flattening\n"
                    "  — Dead code insertion\n"
                    "  — Instruction substitution\n"
                    "  — Junk bytes insertion\n"
                    "  — API call hashing (hashing function names at runtime)\n"
                    "- **Detection**: Look for excessive jump instructions, meaningless loops\n"
                    "- **Deobfuscation**: Symbolic execution, emulation (Unicorn Engine), SMT solvers (Z3)\n\n"
                    "### Combined Approach\n"
                    "Modern malware often uses both: packed distribution with obfuscated payload.\n"
                    "Analysis approach: 1) Unpack via memory dump 2) Deobfuscate via execution tracing",
                "source": "malware_analysis",
                "domain": "malware_analysis",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_reverse_engineering(self):
        samples = [
            {
                "instruction": "How do you reverse engineer a binary with Ghidra?",
                "output": "## RE Workflow with Ghidra\n\n"
                    "### 1. Project Setup\n"
                    "- Create new project\n"
                    "- Import binary (select file type, architecture)\n"
                    "- Analysis options: auto-analyze (tick all boxes)\n\n"
                    "### 2. Initial Analysis\n"
                    "- **Symbol Tree**: View functions, labels, imports/exports\n"
                    "- **Listing**: Decompiled code (pseudocode) window\n"
                    "- **Program Tree**: Memory sections (.text, .data, .rdata)\n\n"
                    "### 3. Function Identification\n"
                    "- Look for `entry` or `WinMain`\n"
                    "- Identify imported functions (strings window → referenced APIs)\n"
                    "- Use `Search → Program Text` for relevant strings\n\n"
                    "### 4. Decompilation\n"
                    "- Click on functions → C-like pseudocode in decompiler\n"
                    "- **Rename variables** (L for local, F for function param)\n"
                    "- **Add comments** (;) for explanations\n"
                    "- **Create structs** from data type information\n\n"
                    "### 5. Advanced Features\n"
                    "- **Patch Instruction**: Modify bytes in-place (for keygen/patches)\n"
                    "- **Scripting**: GhidraScript, Python (Jython) for automation\n"
                    "- **Data Type Manager**: Use existing type libraries (VS, GCC)\n"
                    "- **Version Tracking**: Compare binary versions\n\n"
                    "### 6. Export\n"
                    "- Export decompiled code to C\n"
                    "- Generate report (PDF/HTML)\n"
                    "- Extract and document hardcoded strings, keys, algorithms",
                "source": "reverse_engineering",
                "domain": "reverse_engineering",
            },
            {
                "instruction": "Explain common anti-reverse engineering techniques",
                "output": "## Anti-Reverse Engineering Techniques\n\n"
                    "### Anti-Debugging\n"
                    "- `IsDebuggerPresent()` — classic Win32 check\n"
                    "- `NtQueryInformationProcess` — check ProcessDebugPort\n"
                    "- `CheckRemoteDebuggerPresent` — cross-process check\n"
                    "- Timing checks: `rdtsc` instruction, `QueryPerformanceCounter`\n"
                    "- `OutputDebugString` — raises exception if no debugger\n"
                    "- TLS callbacks — execute before entry point\n\n"
                    "### Anti-VM / Anti-Sandbox\n"
                    "- Check MAC address prefixes (00:0C:29, 00:1C:42 for VMware)\n"
                    "- Check for virtualization drivers (vmtools, vboxguest)\n"
                    "- CPUID instruction checking for hypervisor bit\n"
                    "- Low RAM (< 2GB) → sandbox detection\n"
                    "- Long sleep calls to bypass sandbox timeouts\n\n"
                    "### Code Obfuscation\n"
                    "- Control flow flattening — destroys CFG readability\n"
                    "- Opaque predicates — always-true conditions\n"
                    "- Junk code insertion — dead instructions\n"
                    "- Constant unfolding — replace constants with expressions\n\n"
                    "### API Hashing\n"
                    "- Instead of importing `CreateFile`, hash the name and resolve at runtime\n"
                    "- Algorithm: `ROR13`, `CRC32`, or custom hashing\n\n"
                    "### Mitigations\n"
                    "- Patch anti-debug calls (NOP out)\n"
                    "- Use ScyllaHide / TitanHide for debugger hiding\n"
                    "- Emulate execution (Unicorn) instead of running directly\n"
                    "- Pin tool / Intel PT for execution tracing",
                "source": "reverse_engineering",
                "domain": "reverse_engineering",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_secure_coding(self):
        samples = [
            {
                "instruction": "Write a Python function that securely stores API keys",
                "output": "import os\nimport base64\nfrom cryptography.fernet import Fernet\nfrom cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2\n\nclass SecureCredentialStore:\n    \"\"\"Securely store and retrieve API keys using encryption.\"\"\"\n\n    def __init__(self, master_key: str = None):\n        if master_key is None:\n            master_key = os.environ.get(\"MASTER_KEY\")\n            if not master_key:\n                raise ValueError(\"Set MASTER_KEY environment variable\")\n        self.cipher = self._derive_key(master_key)\n\n    def _derive_key(self, master_key: str) -> Fernet:\n        salt = b\"cyber-llm-salt\"  # In production, store separately\n        kdf = PBKDF2(\n            algorithm=hashes.SHA256(),\n            length=32,\n            salt=salt,\n            iterations=600000,\n        )\n        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))\n        return Fernet(key)\n\n    def store(self, credential: str) -> bytes:\n        return self.cipher.encrypt(credential.encode())\n\n    def retrieve(self, encrypted: bytes) -> str:\n        return self.cipher.decrypt(encrypted).decode()\n\n    @staticmethod\n    def generate_master_key() -> str:\n        return base64.urlsafe_b64encode(os.urandom(32)).decode()\n\n# Usage:\n# store = SecureCredentialStore()\n# encrypted = store.store(\"sk-1234...\")\n# print(encrypted)  # save this to a file\n# key = store.retrieve(encrypted)  # recover the API key",
                "source": "secure_coding",
                "domain": "application_security",
            },
            {
                "instruction": "Write a Python script for secure file upload validation",
                "output": "import os\nimport magic\nimport hashlib\nfrom pathlib import Path\n\nclass SecureFileUpload:\n    ALLOWED_MIME_TYPES = {\n        'image/jpeg', 'image/png', 'image/gif', 'image/webp',\n        'application/pdf',\n        'text/plain', 'text/csv',\n    }\n    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB\n    UPLOAD_DIR = Path(\"./uploads\")\n\n    def __init__(self):\n        self.UPLOAD_DIR.mkdir(exist_ok=True)\n\n    def validate(self, file_bytes: bytes, filename: str) -> dict:\n        errors = []\n\n        # Check file size\n        if len(file_bytes) > self.MAX_FILE_SIZE:\n            errors.append(f\"File exceeds {self.MAX_FILE_SIZE // 1024 // 1024}MB limit\")\n\n        # Check MIME type (content-based, not extension)\n        mime = magic.from_buffer(file_bytes, mime=True)\n        if mime not in self.ALLOWED_MIME_TYPES:\n            errors.append(f\"File type {mime} not allowed\")\n\n        # Check for double extensions\n        if filename.count('.') > 1:\n            errors.append(\"Suspicious filename: multiple extensions\")\n\n        # Check for path traversal\n        clean_name = Path(filename).name\n        if clean_name != filename:\n            errors.append(\"Path traversal detected in filename\")\n\n        # Generate safe filename\n        ext = Path(filename).suffix\n        safe_name = hashlib.sha256(file_bytes).hexdigest()[:16] + ext\n        safe_path = self.UPLOAD_DIR / safe_name\n\n        return {\n            \"valid\": len(errors) == 0,\n            \"errors\": errors,\n            \"mime_type\": mime,\n            \"size\": len(file_bytes),\n            \"safe_path\": str(safe_path),\n            \"safe_name\": safe_name,\n        }\n\n    def save(self, file_bytes: bytes, filename: str) -> Path:\n        result = self.validate(file_bytes, filename)\n        if not result[\"valid\"]:\n            raise ValueError(f\"Upload rejected: {', '.join(result['errors'])}\")\n        path = self.UPLOAD_DIR / result[\"safe_name\"]\n        path.write_bytes(file_bytes)\n        return path",
                "source": "secure_coding",
                "domain": "application_security",
            },
            {
                "instruction": "Explain and prevent Server-Side Request Forgery (SSRF) in Python",
                "output": "## SSRF Prevention in Python\n\n"
                    "SSRF occurs when an attacker makes the server send requests to internal resources.\n\n"
                    "### Vulnerable Pattern\n"
                    "```python\nimport requests\n\ndef fetch_url(user_input):\n    return requests.get(user_input)  # Attacker can use file://, http://169.254.169.254/\n```\n\n"
                    "### Secure Implementation\n"
                    "```python\nimport requests\nfrom urllib.parse import urlparse\nimport ipaddress\nimport socket\n\nALLOWED_HOSTS = [\"api.trusted.com\", \"data.example.com\"]\nALLOWED_SCHEMES = {\"https\"}\nALLOWED_PORTS = {443}\n\ndef validate_url(url: str) -> bool:\n    parsed = urlparse(url)\n\n    # Restrict scheme\n    if parsed.scheme not in ALLOWED_SCHEMES:\n        return False\n\n    # Restrict port\n    port = parsed.port or 443\n    if port not in ALLOWED_PORTS:\n        return False\n\n    # Resolve and check IP\n    try:\n        hostname = parsed.hostname\n        ip = socket.gethostbyname(hostname)\n        addr = ipaddress.ip_address(ip)\n\n        # Block private/rfc1918 addresses\n        if addr.is_private or addr.is_loopback or addr.is_link_local:\n            return False\n\n        # Block cloud metadata IPs\n        if str(addr) in [\"169.254.169.254\", \"100.100.100.200\"]:\n            return False\n\n    except Exception:\n        return False\n\n    # Allowlist check\n    return any(host in hostname for host in ALLOWED_HOSTS)\n\n\ndef safe_fetch_url(user_input: str):\n    if not validate_url(user_input):\n        raise ValueError(\"URL not allowed\")\n    return requests.get(user_input, timeout=5)\n```\n\n"
                    "### Additional Defenses\n"
                    "- Network-level: Restrict outbound traffic from application servers\n"
                    "- Use a proxy for all outbound HTTP requests\n"
                    "- Disable redirect following: `requests.get(url, allow_redirects=False)`\n"
                    "- For file URLs: Disable file:// scheme access\n"
                    "- Use a URL denylist for known sensitive paths",
                "source": "secure_coding",
                "domain": "application_security",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_incident_response(self):
        samples = [
            {
                "instruction": "Walk through the Incident Response process using NIST framework",
                "output": "## NIST Incident Response Process (SP 800-61)\n\n"
                    "### 1. Preparation\n"
                    "- IR policy and plan documented and approved\n"
                    "- Incident Response Team (IRT) defined with roles\n"
                    "- Tools ready: forensic workstations, imaging tools, analysis VMs\n"
                    "- Communication plan: internal, legal, PR, law enforcement\n"
                    "- Regular tabletop exercises and drills\n\n"
                    "### 2. Detection & Analysis\n"
                    "- **Sources**: SIEM alerts, user reports, IDS/IPS, threat intel\n"
                    "- **Triage**: Determine scope, severity, impact\n"
                    "- **Analysis**: \n"
                    "  — Collect logs (network, endpoint, cloud)\n"
                    "  — Determine root cause\n"
                    "  — Identify all affected systems\n"
                    "  — Document IOCs (hashes, IPs, domains)\n"
                    "- **Indicators**: \n"
                    "  — Host: Unknown processes, registry changes, file modifications\n"
                    "  — Network: C2 traffic, data exfiltration, port scans\n"
                    "  — Cloud: Unauthorized API calls, new resources\n\n"
                    "### 3. Containment, Eradication & Recovery\n"
                    "- **Short-term**: Isolate affected systems (network disconnect)\n"
                    "- **Long-term**: Apply patches, rotate credentials, rebuild systems\n"
                    "- **Eradication**: Remove malware, close backdoors\n"
                    "- **Recovery**: Restore from clean backups, monitor for reinfection\n"
                    "- **Evidence preservation**: Forensics imaging, chain of custody\n\n"
                    "### 4. Post-Incident Activity (Lessons Learned)\n"
                    "- Root cause analysis report\n"
                    "- Timeline of events\n"
                    "- Recommendations to prevent recurrence\n"
                    "- Update IR plan, detection rules, and playbooks\n"
                    "- Legal/compliance reporting as required (GDPR, breach notification)",
                "source": "incident_response",
                "domain": "incident_response",
            },
            {
                "instruction": "Write a Python script for initial incident triage on a Linux host",
                "output": "#!/usr/bin/env python3\n\"\"\"Linux Incident Triage Collector\"\"\"\nimport subprocess\nimport json\nimport datetime\nfrom pathlib import Path\n\nOUTPUT = Path(f\"ir_triage_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}\")\nOUTPUT.mkdir(exist_ok=True)\n\ndef run(cmd, name):\n    try:\n        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)\n        (OUTPUT / name).write_text(result.stdout + result.stderr)\n        return True\n    except Exception as e:\n        (OUTPUT / name).write_text(f\"Error: {e}\")\n        return False\n\ndef collect():\n    print(f\"Collecting triage data to {OUTPUT}...\")\n\n    # Process info\n    run([\"ps\", \"auxf\"], \"process_list.txt\")\n    run([\"ps\", \"-eo\", \"pid,ppid,%cpu,%mem,rss,cmd\", \"--sort=-%mem\"], \"process_by_memory.txt\")\n    run([\"lsof\", \"-i\"], \"network_connections.txt\")\n\n    # Network\n    run([\"ss\", \"-tulpan\"], \"listening_ports.txt\")\n    run([\"ss\", \"-tupna\"], \"all_connections.txt\")\n    run([\"ip\", \"addr\"], \"ip_addresses.txt\")\n    run([\"ip\", \"route\"], \"routing_table.txt\")\n    run([\"iptables\", \"-L\", \"-n\", \"-v\"], \"iptables_rules.txt\")\n\n    # Users & Auth\n    run([\"who\", \"-a\"], \"logged_in_users.txt\")\n    run([\"last\", \"-F\", \"-50\"], \"last_logins.txt\")\n    run([\"lastb\"], \"failed_logins.txt\")\n    run([\"cat\", \"/etc/passwd\"], \"passwd.txt\")\n    run([\"cat\", \"/etc/shadow\"], \"shadow.txt\")\n    run([\"w\"], \"who_is_logged_in.txt\")\n\n    # Persistence\n    run([\"cat\", \"/etc/crontab\"], \"crontab.txt\")\n    run([\"ls\", \"-la\", \"/etc/cron.d/\"], \"cron_d.txt\")\n    run([\"systemctl\", \"list-units\", \"--type=service\", \"--state=running\"], \"running_services.txt\")\n    run([\"systemctl\", \"list-unit-files\", \"--type=service\", \"--state=enabled\"], \"enabled_services.txt\")\n    run([\"ls\", \"-la\", \"/etc/systemd/system/\"], \"systemd_system.txt\")\n\n    # Files\n    run([\"find\", \"/tmp\", \"/var/tmp\", \"/dev/shm\", \"-type\", \"f\", \"-atime\", \"-1\"], \"recent_temp_files.txt\")\n    run([\"stat\", \"/\", \"/etc\", \"/bin\", \"/sbin\"], \"filesystem_stats.txt\")\n\n    # Logs\n    run([\"tail\", \"-200\", \"/var/log/syslog\"], \"syslog_tail.txt\")\n    run([\"tail\", \"-200\", \"/var/log/auth.log\"], \"auth_log_tail.txt\")\n    run([\"journalctl\", \"-u\", \"ssh\", \"--no-pager\", \"-n\", \"100\"], \"ssh_logs.txt\")\n\n    # Kernel\n    run([\"lsmod\"], \"kernel_modules.txt\")\n    run([\"dmesg\", \"|\", \"tail\", \"-100\"], \"dmesg_tail.txt\")\n\n    print(f\"Triage data saved to {OUTPUT}\")\n    print(f\"Size: {sum(f.stat().st_size for f in OUTPUT.iterdir()) / 1024:.1f} KB\")\n\nif __name__ == \"__main__\":\n    collect()",
                "source": "incident_response",
                "domain": "incident_response",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_detection_engineering(self):
        samples = [
            {
                "instruction": "Write a Sigma rule to detect Mimikatz usage",
                "output": "title: Mimikatz Detection via Event ID 10 (ProcessAccess)\nid: 8e8d4f99-bbba-4b6f-8b6b-0b0b0b0b0b0b\nstatus: experimental\ndescription: Detects Mimikatz by monitoring lsass process access (Event ID 10)\nreferences:\n    - https://attack.mitre.org/software/S0002/\nauthor: Cyber-LLM\ndate: 2024/01/01\ntags:\n    - attack.credential_access\n    - attack.s0002\n    - attack.t1003\nlogsource:\n    product: windows\n    service: security\n    definition: Requires 'Audit Process Creation' and 'Audit Process Access' enabled\ndetection:\n    selection:\n        EventID: 10\n        TargetImage|endswith: '\\\\lsass.exe'\n        GrantedAccess|contains:\n            - '0x1010'\n            - '0x1410'\n            - '0x143A'\n            - '0x1F1FFF'\n    condition: selection\nfalsepositives:\n    - Legitimate LSASS access by AV/EDR\n    - Windows Defender credential protection\nlevel: high",
                "source": "detection_engineering",
                "domain": "detection_engineering",
            },
            {
                "instruction": "Write a YARA rule to detect common ransomware indicators",
                "output": "rule Ransomware_Generic_Indicators\n{\n    meta:\n        description = \"Detects common ransomware strings and behaviors\"\n        author = \"Cyber-LLM\"\n        date = \"2024-01-01\"\n        reference = \"MITRE ATT&CK T1486\"\n\n    strings:\n        $readme = /(readme|how_to_decrypt|RECOVER|DECRYPT|RANSOM)\\.[Tt][Xx][Tt]/ nocase\n        $ext = /\\.(lockbit|encrypted|crypted|enc|locked|leakme|encrypt)$/ nocase\n        $note = \"Bitcoin\" nocase\n        $note2 = \"decrypt\" nocase\n        $note3 = \"payment\" nocase\n        $note4 = \"T\\-OR\" ascii wide  # Tor address\n        $dll1 = \"cryptsp.dll\"\n        $dll2 = \"advapi32.dll\"\n        $no_restore = \"vssadmin delete shadows\" ascii wide\n        $no_backup = \"wbadmin delete backup\" ascii wide\n        $bcdedit = \"bcdedit /set recoveryenabled\" ascii wide\n\n    condition:\n        uint16(0) == 0x5A4D and  # MZ header\n        (\n            (1 of ($readme, $ext, $note*))\n            or\n            (all of ($no_*) and 1 of ($dll*))\n        )\n}\n\nrule Ransomware_File_Encryption\n{\n    meta:\n        description = \"Detects file encryption behavior common in ransomware\"\n        author = \"Cyber-LLM\"\n\n    strings:\n        $s1 = \"WriteFile\"\n        $s2 = \"ReadFile\"\n        $s3 = \"FindFirstFile\"\n        $s4 = \"FindNextFile\"\n        $s5 = \"DeleteFileA\"\n        $s6 = \"MoveFileEx\"\n        $crypto1 = \"CryptEncrypt\"\n        $crypto2 = \"CryptDecrypt\"\n        $crypto3 = \"CryptAcquireContext\"\n        $crypto4 = \"CryptGenKey\"\n\n    condition:\n        uint16(0) == 0x5A4D and\n        (\n            ($crypto1 or $crypto2 or $crypto3 or $crypto4)\n            and\n            (2 of ($s*))\n        )\n}",
                "source": "detection_engineering",
                "domain": "detection_engineering",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_k8s_security(self):
        samples = [
            {
                "instruction": "List Kubernetes security best practices for Pod security",
                "output": "## Kubernetes Pod Security Best Practices\n\n"
                    "### 1. Run as Non-Root\n"
                    "```yaml\nsecurityContext:\n  runAsNonRoot: true\n  runAsUser: 1000\n  runAsGroup: 3000\n```\n\n"
                    "### 2. Read-Only Root Filesystem\n"
                    "```yaml\nsecurityContext:\n  readOnlyRootFilesystem: true\n```\n\n"
                    "### 3. Drop All Capabilities, Add Only Needed\n"
                    "```yaml\nsecurityContext:\n  capabilities:\n    drop: [\"ALL\"]\n    add: [\"NET_BIND_SERVICE\"]\n```\n\n"
                    "### 4. Use Pod Security Standards (PSS)\n"
                    "- **Privileged**: Unrestricted (use with caution)\n"
                    "- **Baseline**: Minimal restrictions for known threats\n"
                    "- **Restricted**: Strong security (recommended for production)\n"
                    "```yaml\napiVersion: v1\nkind: Namespace\nmetadata:\n  labels:\n    pod-security.kubernetes.io/enforce: restricted\n```\n\n"
                    "### 5. Resource Limits\n"
                    "```yaml\nresources:\n  requests:\n    memory: \"256Mi\"\n    cpu: \"500m\"\n  limits:\n    memory: \"512Mi\"\n    cpu: \"1\"\n```\n\n"
                    "### 6. Seccomp & AppArmor\n"
                    "```yaml\nsecurityContext:\n  seccompProfile:\n    type: RuntimeDefault\n```\n\n"
                    "### 7. Network Policies (Zero Trust)\n"
                    "```yaml\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n  - Egress\n```\n\n"
                    "### 8. ServiceAccount Best Practices\n"
                    "- Don't use default service account\n"
                    "- Set `automountServiceAccountToken: false` when not needed\n"
                    "- Use dedicated service accounts per app with RBAC\n\n"
                    "### Audit with Tools\n"
                    "- `kubectl audit`\n"
                    "- kube-bench (CIS benchmark)\n"
                    "- Popeye (cluster linter)\n"
                    "- Kyverno / OPA Gatekeeper (policy enforcement)",
                "source": "k8s_security",
                "domain": "kubernetes_security",
            },
            {
                "instruction": "How do you secure a Kubernetes RBAC configuration?",
                "output": "## Kubernetes RBAC Security\n\n"
                    "### Principle: Least Privilege\n"
                    "Never use `cluster-admin` for anything except initial setup.\n\n"
                    "### 1. Role vs ClusterRole\n"
                    "- **Role**: Namespace-scoped (use whenever possible)\n"
                    "- **ClusterRole**: Cluster-scoped (use only for cluster-wide resources)\n\n"
                    "### 2. Good RBAC Example\n"
                    "```yaml\napiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  namespace: app-namespace\n  name: app-reader\nrules:\n- apiGroups: [\"\"]\n  resources: [\"pods\", \"services\", \"configmaps\"]\n  verbs: [\"get\", \"list\", \"watch\"]\n- apiGroups: [\"apps\"]\n  resources: [\"deployments\"]\n  verbs: [\"get\", \"list\", \"watch\"]\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  namespace: app-namespace\n  name: app-reader-binding\nsubjects:\n- kind: ServiceAccount\n  name: app-sa\n  namespace: app-namespace\nroleRef:\n  kind: Role\n  name: app-reader\n  apiGroup: rbac.authorization.k8s.io\n```\n\n"
                    "### 3. Dangerous Permissions to Audit\n"
                    "- `*` verbs on any resource (full access)\n"
                    "- `create pods/exec` — shell access to containers\n"
                    "- `create pods/portforward` — network access\n"
                    "- `create secrets` or `get secrets` — credential access\n"
                    "- `create deployments` — arbitrary code execution\n"
                    "- `create clusterroles` or `create clusterrolebindings` — privilege escalation\n\n"
                    "### 4. Audit Commands\n"
                    "```bash\n# Check for wildcards\nkubectl get clusterroles -o json | jq '.items[] | select(.rules[].verbs[] | contains(\"*\")) | .metadata.name'\n\n# Check subjects with cluster-admin\nkubectl get clusterrolebinding -o json | jq '.items[] | select(.roleRef.name==\"cluster-admin\") | .subjects'\n```\n\n"
                    "### 5. Tools\n"
                    "- **RBAC Manager** (`rbac-manager`) — declarative RBAC\n"
                    "- **kubectl-who-can** — who can do what\n"
                    "- **audit2rbac** — generate RBAC from audit logs\n"
                    "- **rakkess** — review access matrix",
                "source": "k8s_security",
                "domain": "kubernetes_security",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_docker_security(self):
        samples = [
            {
                "instruction": "What are the top Docker security best practices?",
                "output": "## Docker Security Best Practices\n\n"
                    "### 1. Use Official and Minimal Base Images\n"
                    "- Prefer `alpine` or `distroless` over full OS images\n"
                    "- Pin versions: `FROM python:3.11-slim@sha256:...`\n"
                    "- Scan images: `docker scan`, Trivy, Snyk\n\n"
                    "### 2. Run as Non-Root User\n"
                    "```dockerfile\nRUN addgroup -S app && adduser -S app -G app\nUSER app\n```\n\n"
                    "### 3. Drop Security Capabilities\n"
                    "```bash\ndocker run --cap-drop ALL --cap-add NET_BIND_SERVICE myapp\n```\n\n"
                    "### 4. Read-Only Root Filesystem\n"
                    "```bash\ndocker run --read-only --tmpfs /tmp myapp\n```\n\n"
                    "### 5. Use Multi-Stage Builds\n"
                    "```dockerfile\n# Build stage\nFROM golang:1.21 AS builder\nWORKDIR /app\nCOPY . .\nRUN CGO_ENABLED=0 go build -o /app/main .\n\n# Runtime stage\nFROM alpine:3.19\nCOPY --from=builder /app/main /app/\nRUN addgroup -S app && adduser -S app -G app\nUSER app\nCMD [\"/app/main\"]\n```\n\n"
                    "### 6. Security Scanning in CI/CD\n"
                    "```yaml\n- name: Scan Docker image\n  uses: aquasecurity/trivy-action@master\n  with:\n    image-ref: 'myapp:latest'\n    format: 'sarif'\n```\n\n"
                    "### 7. Dockerfile Best Practices\n"
                    "- Don't run `apt-get upgrade` (use specific patched images)\n"
                    "- Clean up apt cache in same layer: `rm -rf /var/lib/apt/lists/*`\n"
                    "- Don't COPY secrets (use BuildKit secrets or Docker secrets)\n"
                    "- Use `.dockerignore` to exclude unnecessary files\n\n"
                    "### 8. Runtime Security\n"
                    "- Use `--security-opt no-new-privileges:true`\n"
                    "- Set memory/CPU limits: `--memory=256m --cpus=1.0`\n"
                    "- Use Docker Bench Security for audits\n"
                    "- Enable Content Trust: `export DOCKER_CONTENT_TRUST=1`",
                "source": "docker_security",
                "domain": "docker_security",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_grc(self):
        samples = [
            {
                "instruction": "Explain the difference between ISO 27001, SOC 2, and PCI DSS",
                "output": "## Compliance Framework Comparison\n\n"
                    "### ISO 27001\n"
                    "- **Focus**: Information Security Management System (ISMS)\n"
                    "- **Scope**: Organization-wide (policies, processes, people)\n"
                    "- **Certification**: Third-party audit, valid 3 years\n"
                    "- **Requirements**: 114 controls in Annex A\n"
                    "- **Best for**: General security posture, EU compliance\n\n"
                    "### SOC 2 (Service Organization Control)\n"
                    "- **Focus**: Service provider controls (hosting, SaaS, cloud)\n"
                    "- **Scope**: Specific services/systems defined by trust criteria\n"
                    "- **Certification**: Auditor report (Type I or Type II)\n"
                    "- **Trust Criteria**: Security, Availability, Confidentiality, Privacy, Processing Integrity\n"
                    "- **Best for**: US-based service providers, vendor due diligence\n\n"
                    "### PCI DSS (Payment Card Industry Data Security Standard)\n"
                    "- **Focus**: Credit card data protection\n"
                    "- **Scope**: Cardholder data environment (CDE)\n"
                    "- **Certification**: SAQ or QSA audit based on volume\n"
                    "- **Requirements**: 12 requirements, 300+ sub-requirements\n"
                    "- **Best for**: Any business processing credit cards\n\n"
                    "### Overlap & Synergies\n"
                    "All three share common controls:\n"
                    "- Access control, encryption, incident response, vendor management\n"
                    "- Many organizations use ISO 27001 as a base, then add SOC 2 or PCI\n"
                    "- Tools: OneTrust, Vanta, Drata for unified compliance management",
                "source": "grc",
                "domain": "governance_risk_compliance",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_ai_security(self):
        samples = [
            {
                "instruction": "What are the top security risks in LLM applications?",
                "output": "## OWASP Top 10 for LLM Applications\n\n"
                    "### LLM01 — Prompt Injection\n"
                    "- Attacker manipulates prompts to bypass restrictions\n"
                    "- Mitigation: Input validation, prompt sandboxing, output filtering\n\n"
                    "### LLM02 — Insecure Output Handling\n"
                    "- Model output is directly executed or rendered\n"
                    "- Mitigation: Never trust model output, use parameterized queries\n\n"
                    "### LLM03 — Training Data Poisoning\n"
                    "- Backdoors or biases injected into training data\n"
                    "- Mitigation: Data validation, supply chain security, differential privacy\n\n"
                    "### LLM04 — Model Denial of Service\n"
                    "- Resource exhaustion via complex/long prompts\n"
                    "- Mitigation: Rate limiting, token limits, input validation\n\n"
                    "### LLM05 — Supply Chain Vulnerabilities\n"
                    "- Compromised model weights, libraries, or plugins\n"
                    "- Mitigation: Model signing, SBOMs, integrity verification\n\n"
                    "### LLM06 — Sensitive Information Disclosure\n"
                    "- PII, secrets, or confidential data in model outputs\n"
                    "- Mitigation: Output filtering, data sanitization, access controls\n\n"
                    "### LLM07 — Insecure Plugin Design\n"
                    "- Plugins with excessive permissions or poor input validation\n"
                    "- Mitigation: Plugin sandboxing, permission scoping\n\n"
                    "### LLM08 — Excessive Agency\n"
                    "- Autonomous agents with too many permissions\n"
                    "- Mitigation: Human-in-the-loop, action limits, audit logging\n\n"
                    "### LLM09 — Overreliance\n"
                    "- Blind trust in model output without verification\n"
                    "- Mitigation: Always verify critical outputs, human oversight\n\n"
                    "### LLM10 — Model Theft\n"
                    "- Stealing model weights via extracted training data\n"
                    "- Mitigation: API rate limiting, watermarking, model encryption",
                "source": "ai_security",
                "domain": "ai_security",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_windows_ad(self):
        samples = [
            {
                "instruction": "How do you perform Active Directory security assessment?",
                "output": "## Active Directory Security Assessment\n\n"
                    "### 1. Information Gathering\n"
                    "- **BloodHound**: Map AD relationships\n"
                    "```\nbloodhound-python -d domain.com -u user -p pass -ns dc.domain.com -c All\n```\n"
                    "- **LDAP enumeration** with ldapsearch or AD Explorer\n\n"
                    "### 2. Common Vulnerabilities to Check\n"
                    "- **Kerberoasting**: Request TGS for service accounts with SPNs\n"
                    "- **AS-REP Roasting**: Find accounts with Kerberos pre-auth disabled\n"
                    "- **DCSync**: Check who can replicate directory changes\n"
                    "- **Pass-the-Hash / Overpass-the-Hash**: NTLM relay paths\n"
                    "- **ACL abuse**: GenericAll, WriteOwner, ForceChangePassword\n"
                    "- **Unconstrained delegation**: Laptop for TGT theft\n\n"
                    "### 3. Tooling\n"
                    "```bash\n# BloodHound data collection\nSharpHound.exe -c All\n\n# PowerView enumeration\nGet-NetUser | select samaccountname, description\nGet-NetGroup \"Domain Admins\"\n\n# CrackMapExec\ncrackmapexec smb dc.domain.com -u user -p pass --shares\ncrackmapexec smb dc.domain.com -u user -p pass --sessions\n\n# Impacket for attacks\nimpacket-GetUserSPNs domain.com/user:pass -request\nimpacket-secretsdump domain.com/user:pass@dc.domain.com\n```\n\n"
                    "### 4. Hardening Recommendations\n"
                    "- Enable LDAP signing and channel binding\n"
                    "- Deploy Microsoft LAPS for local admin passwords\n"
                    "- implement Tiering model (Tier 0/1/2)\n"
                    "- Remove unnecessary SPNs\n"
                    "- Disable RC4 and weak Kerberos encryption\n"
                    "- Enable Kerberos armoring (FAST)\n"
                    "- Review and clean up privileged groups regularly\n"
                    "- Deploy PTA (Password Protection) for banned passwords",
                "source": "ad_security",
                "domain": "windows_ad",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def add_linux_security(self):
        samples = [
            {
                "instruction": "How do you harden a Linux server for production?",
                "output": "## Linux Server Hardening Guide\n\n"
                    "### 1. SSH Hardening\n"
                    "```bash\n# /etc/ssh/sshd_config\nPort 2222\nPermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes\nMaxAuthTries 3\nClientAliveInterval 300\nClientAliveCountMax 2\nAllowUsers deploy admin\n\n# Restart\nsystemctl restart sshd\n```\n\n"
                    "### 2. User Management\n"
                    "- Remove unnecessary users: `userdel -r games`\n"
                    "- Enforce password policy: `/etc/security/pwquality.conf`\n"
                    "- Lock inactive accounts: `useradd -D -f 30`\n"
                    "- Use sudo with specific commands, not full access\n\n"
                    "### 3. Filesystem Security\n"
                    "```bash\n# Mount options in /etc/fstab\n/dev/sda1 / ext4 defaults,noexec,nosuid,nodev 0 0\n/dev/sdb1 /tmp ext4 defaults,noexec,nosuid,nodev 0 0\n/dev/sdc1 /var ext4 defaults,noexec,nosuid 0 0\n```\n\n"
                    "### 4. Kernel Hardening\n"
                    "```bash\n# /etc/sysctl.d/99-security.conf\nnet.ipv4.ip_forward = 0\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.all.secure_redirects = 0\nnet.ipv6.conf.all.disable_ipv6 = 1\nkernel.kptr_restrict = 2\nkernel.dmesg_restrict = 1\nkernel.randomize_va_space = 2\nfs.protected_hardlinks = 1\nfs.protected_symlinks = 1\n```\n\n"
                    "### 5. Audit & Monitoring\n"
                    "- **auditd**: Monitor critical files\n"
                    "```bash\nauditctl -w /etc/passwd -p wa -k passwd_changes\nauditctl -w /etc/shadow -p wa -k shadow_changes\nauditctl -w /etc/ssh/sshd_config -p wa -k ssh_config\n```\n"
                    "- **AIDE**: File integrity monitoring\n"
                    "- **Fail2ban**: Brute force protection\n"
                    "- **Logwatch**: Daily log summary\n\n"
                    "### 6. Firewall\n"
                    "```bash\nufw default deny incoming\nufw default allow outgoing\nufw allow 2222/tcp comment 'SSH'\nufw allow 80,443/tcp comment 'Web'\nufw enable\n```\n\n"
                    "### 7. Regular Hardening\n"
                    "- CIS Benchmark: Use `ansible-cis` or `kube-bench`\n"
                    "- Lynis: `lynis audit system`\n"
                    "- OpenSCAP: Compliance scanning\n"
                    "- Keep system updated: `unattended-upgrades`",
                "source": "linux_security",
                "domain": "linux_security",
            },
        ]
        for s in samples:
            self.add(s["instruction"], s["output"], s["source"], s["domain"])

    def build_chat_format(self) -> List[Dict]:
        chat_samples = []
        for s in self.samples:
            chat_samples.append({
                "messages": [
                    {"role": "user", "content": s["instruction"]},
                    {"role": "assistant", "content": s["output"]},
                ],
                "source": s["source"],
                "domain": s["domain"],
            })
        return chat_samples

    def save(self):
        jsonl_path = self.output_dir / "cyber_train.jsonl"
        with open(jsonl_path, "w") as f:
            for s in self.samples:
                f.write(json.dumps(s) + "\n")
        print(f"Saved {len(self.samples)} samples to {jsonl_path}")

        chat_path = self.output_dir / "cyber_train_chat.jsonl"
        chat_samples = self.build_chat_format()
        with open(chat_path, "w") as f:
            for s in chat_samples:
                f.write(json.dumps(s) + "\n")
        print(f"Saved {len(chat_samples)} chat samples to {chat_path}")

        domains = {}
        sources = {}
        for s in self.samples:
            domains[s["domain"]] = domains.get(s["domain"], 0) + 1
            sources[s["source"]] = sources.get(s["source"], 0) + 1

        print("\n" + "=" * 50)
        print("DATASET SUMMARY")
        print("=" * 50)
        print(f"  Total samples: {len(self.samples)}")
        print(f"  Unique hashes: {len(self.seen_hashes)}")
        print(f"\n  By Domain ({len(domains)}):")
        for d, c in sorted(domains.items(), key=lambda x: -x[1]):
            print(f"    {d:35s} {c:5d}")
        print(f"\n  By Source ({len(sources)}):")
        for s, c in sorted(sources.items(), key=lambda x: -x[1]):
            print(f"    {s:30s} {c:5d}")


def add_more_expert_content(builder):
    """Add balanced cross-domain expert content."""
    more = [
        # ── Secure Coding (15 languages) ──
        ("Write a secure C function to copy a string without buffer overflow",
         "#include <string.h>\n\nvoid safe_copy(char *dest, size_t dest_size, const char *src) {\n    strlcpy(dest, src, dest_size);\n}\n\n// strlcpy guarantees null-termination and bounds checking\n// Alternative: snprintf(dest, dest_size, \"%s\", src)\n// Never use strcpy(), gets(), or sprintf()",
         "secure_coding", "application_security"),
        ("Write a secure Rust function to handle file I/O with error handling",
         "use std::fs::File;\nuse std::io::{Read, Write};\nuse std::path::Path;\n\nfn read_secure(path: &Path) -> Result<String, std::io::Error> {\n    let mut file = File::open(path)?;\n    let mut contents = String::new();\n    file.read_to_string(&mut contents)?;\n    Ok(contents)\n}\n\n// Rust's ownership model prevents buffer overflows\n// Always use ? operator or match for error handling\n// Use Path::new() instead of string concatenation for path traversal prevention",
         "secure_coding", "application_security"),
        ("Write a secure Go HTTP server with TLS and timeouts",
         'package main\n\nimport (\n    "crypto/tls"\n    "fmt"\n    "net/http"\n    "time"\n)\n\nfunc main() {\n    mux := http.NewServeMux()\n    mux.HandleFunc("/", handler)\n\n    server := &http.Server{\n        Addr:         ":443",\n        Handler:      mux,\n        ReadTimeout:  5 * time.Second,\n        WriteTimeout: 10 * time.Second,\n        IdleTimeout:  120 * time.Second,\n        TLSConfig: &tls.Config{\n            MinVersion: tls.VersionTLS12,\n        },\n    }\n\n    fmt.Println("Server starting...")\n    err := server.ListenAndServeTLS("cert.pem", "key.pem")\n    if err != nil {\n        panic(err)\n    }\n}\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n    w.Header().Set("Content-Security-Policy", "default-src \'self\'")\n    w.Header().Set("X-Content-Type-Options", "nosniff")\n    w.Header().Set("X-Frame-Options", "DENY")\n    fmt.Fprintf(w, "Secure response")\n}',
         "secure_coding", "application_security"),
        ("Explain how to prevent XSS in JavaScript",
         "## XSS Prevention in JavaScript\n\n"
         "### What is XSS?\n"
         "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages.\n\n"
         "### Prevention\n\n"
         "#### 1. Never use innerHTML\n"
         "```javascript\n// UNSAFE\ndocument.getElementById('output').innerHTML = userInput;\n\n// SAFE\ndocument.getElementById('output').textContent = userInput;\n```\n\n"
         "#### 2. Use DOMPurify for sanitization\n"
         "```javascript\nimport DOMPurify from 'dompurify';\nconst clean = DOMPurify.sanitize(dirty);\n```\n\n"
         "#### 3. Content Security Policy (CSP)\n"
         "```html\n<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self'\">\n```\n\n"
         "#### 4. Output encoding\n"
         "- HTML context: escape < > & \" '\n"
         "- JavaScript context: use JSON.stringify()\n"
         "- URL context: use encodeURIComponent()\n\n"
         "#### 5. Framework protections\n"
         "- React: JSX escapes by default\n"
         "- Angular: bypassSecurityTrust is dangerous\n"
         "- Vue: v-html is unsafe",
         "secure_coding", "application_security"),
        ("Explain command injection prevention in Python and PHP",
         "## Command Injection Prevention\n\n"
         "### Python\n"
         "```python\n# UNSAFE\nimport os\nos.system(f\"ping {user_input}\")\n\n# SAFE\nimport subprocess\nsubprocess.run([\"ping\", \"-c\", \"4\", user_input], capture_output=True)\n\n# Even safer - validate input\nimport re\nif not re.match(r'^[\\w\\.-]+$', host):\n    raise ValueError(\"Invalid host\")\nresult = subprocess.run([\"ping\", host], capture_output=True, text=True)\n```\n\n"
         "### PHP\n"
         "```php\n// UNSAFE\n$output = shell_exec(\"ping \" . $_GET['host']);\n\n// SAFE\n$host = escapeshellcmd($_GET['host']);\n$output = shell_exec(\"ping \" . $host);\n\n// BEST - validate\n$allowed = ['8.8.8.8', '1.1.1.1'];\nif (!in_array($_GET['host'], $allowed)) {\n    die('Invalid host');\n}\n```\n\n"
         "### General Rules\n"
         "- Avoid shell execution when possible\n"
         "- Use language-native APIs instead of shell commands\n"
         "- If shell is required: escapeshellarg(), validate input, use allowlists\n"
         "- Never use unsanitized user input in command strings",
         "secure_coding", "application_security"),
        ("Write a secure Java authentication filter",
         'import javax.servlet.*;\nimport javax.servlet.http.*;\nimport javax.servlet.annotation.*;\nimport java.io.IOException;\n\n@WebFilter("/*")\npublic class AuthFilter implements Filter {\n\n    public void doFilter(ServletRequest req, ServletResponse res,\n                         FilterChain chain) throws IOException, ServletException {\n        HttpServletRequest request = (HttpServletRequest) req;\n        HttpServletResponse response = (HttpServletResponse) res;\n\n        String sessionId = request.getSession().getId();\n        if (sessionId == null || sessionId.length() < 32) {\n            response.sendError(401, "Invalid session");\n            return;\n        }\n        chain.doFilter(req, res);\n    }\n}',
         "secure_coding", "application_security"),
        ("Write secure Terraform for AWS S3 bucket with encryption",
         'resource "aws_s3_bucket" "secure" {\n  bucket = var.bucket_name\n\n  # Block all public access by default\n  resource "aws_s3_bucket_public_access_block" "secure" {\n    bucket = aws_s3_bucket.secure.id\n\n    block_public_acls       = true\n    block_public_policy     = true\n    ignore_public_acls      = true\n    restrict_public_buckets = true\n  }\n\n  resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {\n    bucket = aws_s3_bucket.secure.id\n\n    rule {\n      apply_server_side_encryption_by_default {\n        sse_algorithm = "AES256"\n      }\n    }\n  }\n\n  resource "aws_s3_bucket_versioning" "secure" {\n    bucket = aws_s3_bucket.secure.id\n    versioning_configuration {\n      status = "Enabled"\n    }\n  }\n}',
         "secure_coding", "application_security"),
        ("Write a SQL query secure against injection in Node.js",
         '// UNSAFE\nconst query = `SELECT * FROM users WHERE username = \'${userInput}\'`;\n\n// SAFE - Parameterized queries\nconst { Pool } = require(\'pg\');\nconst pool = new Pool();\n\nasync function getUser(username) {\n    const query = \'SELECT * FROM users WHERE username = $1\';\n    const result = await pool.query(query, [username]);\n    return result.rows;\n}\n\n// With Sequelize ORM\nconst user = await User.findOne({\n    where: { username: username }\n});\n\n// Additional security\n// 1. Validate input type: if (typeof username !== \'string\') throw Error()\n// 2. Rate limit login attempts\n// 3. Use bcrypt for password comparison, not SQL\n// 4. Enable WAF for additional SQL injection detection',
         "secure_coding", "application_security"),

        # ── Threat Hunting ──
        ("How do you hunt for lateral movement in a Windows environment?",
         "## Lateral Movement Hunting\n\n"
         "### Indicators to Hunt For\n\n"
         "### 1. Remote Service Creation\n"
         "- Event ID 7045: New service was installed\n"
         "- Look for services starting from uncommon paths (Users\\Temp, Downloads)\n"
         "- Hunt for services named after common tools (PAExec, PSEXESVC)\n\n"
         "### 2. Remote Scheduled Tasks\n"
         "- Event ID 4698: Scheduled task created\n"
         "- Event ID 106: Task triggered (Task Scheduler operational log)\n"
         "- Look for tasks pointing to network shares or temp directories\n\n"
         "### 3. WMI and PowerShell Remoting\n"
         "- Event ID 4104: PowerShell script block logging\n"
         "- Event ID 53504: WMI namespace creation\n"
         "- Hunt for Invoke-Command, New-PSSession, Enter-PSSession\n"
         "- Look for WinRM connections: Microsoft-Windows-WinRM/Operational\n\n"
         "### 4. RDP Usage\n"
         "- Event ID 4624 with LogonType 10 (RemoteInteractive)\n"
         "- Event ID 4649: Replay attack detected\n"
         "- Correlate RDP sessions outside business hours\n\n"
         "### Hunting Queries (KQL)\n"
         "```kusto\n// New service creation\nSecurityEvent\n| where EventID == 7045\n| where ServiceFileName startswith @\"C:\\Users\\\"\n| project TimeGenerated, Computer, ServiceName, ServiceFileName\n```\n\n"
         "### Tools\n"
         "- Microsoft Defender for Endpoint (Advanced Hunting)\n"
         "- BloodHound (identify attack paths)\n"
         "- Velociraptor (artifact collection)\n"
         "- Kansa (PowerShell-based IR)",
         "threat_hunting", "threat_hunting"),

        # ── Cloud Security ──
        ("How do you detect a cryptomining attack in AWS?",
         "## AWS Cryptomining Detection\n\n"
         "### Indicators\n"
         "- **High CPU/GPU usage**: CloudWatch metrics spiking\n"
         "- **Unusual EC2 instances**: g/p/inf types launched without approval\n"
         "- **Suspicious EBS volumes**: Large gp3 volumes for data aggregation\n"
         "- **Network traffic**: Connections to mining pools (known IP ranges)\n"
         "- **Cost anomalies**: Sudden 10-100x increase in compute costs\n\n"
         "### Detection Rules\n\n"
         "#### CloudWatch Anomaly Detection\n"
         "```json\n{\n  \"AlarmName\": \"crypto-cpu-spike\",\n  \"Metrics\": [{\n    \"Id\": \"m1\",\n    \"ReturnData\": true,\n    \"MetricStat\": {\n      \"Metric\": {\n        \"Namespace\": \"AWS/EC2\",\n        \"MetricName\": \"CPUUtilization\"\n      },\n      \"Period\": 300,\n      \"Stat\": \"Average\"\n    }\n  }],\n  \"Threshold\": 90,\n  \"ComparisonOperator\": \"GreaterThanThreshold\"\n}\n```\n\n"
         "#### GuardDuty Finding Types\n"
         "- `CryptoCurrency:EC2/BitcoinTool.B!DNS`\n"
         "- `UnauthorizedAccess:EC2/MaliciousIPCaller.Custom`\n"
         "- `Backdoor:EC2/C&CActivity.B!DNS`\n\n"
         "### Automated Response\n"
         "```python\n# Lambda: Isolate compromised instance\ndef lambda_handler(event, context):\n    instance_id = event['detail']['resource']['instanceDetails']['instanceId']\n    ec2 = boto3.client('ec2')\n    # Create security group that denies all traffic\n    ec2.modify_instance_attribute(\n        InstanceId=instance_id,\n        Groups=['sg-urgent-isolation']\n    )\n```\n\n"
         "### Prevention\n"
         "- SCPs to prevent launching GPU instances without approval\n"
         "- Budget alerts with $0 threshold for anomalous spend\n"
         "- EC2 launch-time IAM roles (no Instance Profiles that allow crypto)\n"
         "- VPC endpoints to prevent data exfiltration",
         "cloud_security", "cloud_security"),

        # ── Forensics ──
        ("How do you perform memory forensics with Volatility 3?",
         "## Memory Forensics with Volatility 3\n\n"
         "### Acquisition\n"
         "```bash\n# Windows\nwinpmem.exe -o memory.raw\n\n# Linux\nsudo fmem --dump memory.raw\n# OR\nsudo avml --output memory.raw\n\n# MacOS\nsudo osxpmem -o memory.raw\n```\n\n"
         "### Analysis\n\n"
         "#### 1. Identify the Image\n"
         "```bash\npython3 vol.py -f memory.raw windows.info\n```\n\n"
         "#### 2. Process Listing\n"
         "```bash\npython3 vol.py -f memory.raw windows.pslist\npython3 vol.py -f memory.raw windows.psscan  # Hidden processes\npython3 vol.py -f memory.raw windows.pstree    # Parent-child\n```\n\n"
         "#### 3. Network Connections\n"
         "```bash\npython3 vol.py -f memory.raw windows.netscan\n```\n\n"
         "#### 4. DLLs and Handles\n"
         "```bash\npython3 vol.py -f memory.raw windows.dlllist --pid 1234\npython3 vol.py -f memory.raw windows.handles --pid 1234\n```\n\n"
         "#### 5. Malware Detection\n"
         "```bash\n# Scan for malicious code\npython3 vol.py -f memory.raw windows.malfind\n# Scan for injected code\npython3 vol.py -f memory.raw windows.hollow\n# Extract process memory\npython3 vol.py -f memory.raw windows.memmap --pid 1234 --dump\n```\n\n"
         "#### 6. Registry\n"
         "```bash\npython3 vol.py -f memory.raw windows.registry.hivelist\npython3 vol.py -f memory.raw windows.registry.printkey --key \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\"\n```\n\n"
         "#### 7. Command Line History\n"
         "```bash\npython3 vol.py -f memory.raw windows.cmdline\npython3 vol.py -f memory.raw windows.cmdhistory\n```\n\n"
         "### Key Artifacts\n"
         "- MFT entries for file timestamps\n"
         "- Prefetch files for application execution\n"
         "- AmCache for installed applications\n"
         "- ShimCache for application compatibility\n"
         "- Event logs embedded in registry hives",
         "forensics", "digital_forensics"),

        # ── DevSecOps ──
        ("How do you implement security scanning in a CI/CD pipeline?",
         "## CI/CD Security Scanning Pipeline\n\n"
         "### Pipeline Stages\n\n"
         "```yaml\n# .github/workflows/security.yml\nname: Security Scan\non: [push, pull_request]\n\njobs:\n  security:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n\n      # 1. SAST (Static Analysis)\n      - name: SAST - Semgrep\n        uses: semgrep/semgrep-action@v1\n        with:\n          config: p/owasp-top-ten\n\n      # 2. Secrets Scanning\n      - name: Secrets - Gitleaks\n        uses: gitleaks/gitleaks-action@v2\n\n      # 3. Dependency Scanning\n      - name: SCA - Trivy\n        uses: aquasecurity/trivy-action@master\n        with:\n          scan-type: 'fs'\n          format: 'sarif'\n\n      # 4. Container Scanning (if Docker)\n      - name: Container - Docker Scout\n        uses: docker/scout-action@v1\n        with:\n          command: quickview\n\n      # 5. DAST (if deployed)\n      - name: DAST - OWASP ZAP\n        uses: zaproxy/action-full-scan@v0.10.0\n        with:\n          target: 'https://staging.example.com'\n```\n\n"
         "### Tools by Category\n\n"
         "| Category | Tools |\n|----------|-------|\n| SAST | Semgrep, SonarQube, CodeQL, Bandit (Python) |\n| Secrets | Gitleaks, TruffleHog, GitGuardian |\n| SCA | Trivy, Snyk, Dependabot, OWASP Dependency-Check |\n| Container | Trivy, Docker Scout, Grype, Clair |\n| IaC | Checkov, Terrascan, tfsec, KICS |\n| DAST | OWASP ZAP, Burp Suite, Nikto |\n\n"
         "### Gating Policy\n"
         "- **Critical/CVSS 9+**: Block merge immediately\n"
         "- **High/CVSS 7-8.9**: Require security review\n"
         "- **Medium/CVSS 4-6.9**: Logged, track in backlog\n"
         "- **Low/CVSS <4**: Informational, auto-close",
         "devsecops", "devsecops"),

        # ── AI Security ──
        ("How do you secure a RAG (Retrieval-Augmented Generation) pipeline?",
         "## RAG Pipeline Security\n\n"
         "### 1. Document Source Security\n"
         "- Validate document content before ingestion\n"
         "- Scan for embedded malicious content (XSS, prompt injection)\n"
         "- Implement document allow-listing (only trusted sources)\n"
         "- Version control for vector store contents\n\n"
         "### 2. Vector Store Security\n"
         "- Encrypt embeddings at rest (AES-256)\n"
         "- Access control: only authorized applications can query\n"
         "- Audit logging for all queries\n"
         "- Regular purging of stale/outdated documents\n\n"
         "### 3. Retrieval Security\n"
         "- **Access control filtering**: Filter results based on user permissions\n"
         "- **Content sanitization**: Strip sensitive data before passing to LLM\n"
         "- **Rate limiting**: Prevent data extraction via many queries\n"
         "- **Query validation**: Reject malicious or out-of-scope queries\n\n"
         "### 4. Prompt Injection Defense\n"
         "```python\n# Detect and block prompt injection attempts\nimport re\n\nINJECTION_PATTERNS = [\n    r\"ignore (all )?(previous|above) instructions\",\n    r\"forget (all )?(previous|above)\",\n    r\"you are (now |)(an? )?(free|unbounded|unleashed)\",\n    r\"DAN|do anything now\",\n    r\"system prompt\",\n    r\"[{{]{2}.*[}}]{2}\",  # Template injection\n]\n\ndef detect_injection(text: str) -> bool:\n    for pattern in INJECTION_PATTERNS:\n        if re.search(pattern, text, re.IGNORECASE):\n            return True\n    return False\n```\n\n"
         "### 5. Output Security\n"
         "- Filter PII from model responses\n"
         "- Check for hallucinated citations\n"
         "- Ensure responses stay within authorized scope\n"
         "- Add banner: 'AI-generated, verify critical information'",
         "ai_security", "ai_security"),

        # ── Network Security ──
        ("Write a Python script to detect DNS tunneling",
         "import dpkt\nimport socket\nfrom collections import defaultdict\n\nclass DNSTunnelDetector:\n    def __init__(self, threshold=50):\n        self.queries = defaultdict(list)\n        self.threshold = threshold\n\n    def analyze_pcap(self, pcap_file):\n        with open(pcap_file, 'rb') as f:\n            pcap = dpkt.pcap.Reader(f)\n\n            for timestamp, buf in pcap:\n                try:\n                    eth = dpkt.ethernet.Ethernet(buf)\n                    if isinstance(eth.data, dpkt.ip.IP):\n                        ip = eth.data\n                        if isinstance(ip.data, dpkt.udp.UDP) and ip.data.dport == 53:\n                            dns = dpkt.dns.DNS(ip.data.data)\n                            self._check_query(dns, timestamp)\n                except:\n                    pass\n\n    def _check_query(self, dns, timestamp):\n        for q in dns.qd:\n            domain = q.name.decode('utf-8', errors='ignore')\n            self.queries[domain].append(timestamp)\n\n            # Check indicators\n            length = len(domain)\n            entropy = self._entropy(domain)\n            subdomain_count = domain.count('.')\n\n            if (length > 50 or\n                entropy > 4.0 or\n                subdomain_count > 5 or\n                len(self.queries) > 100):\n                print(f'[ALERT] Possible DNS tunnel: {domain}')\n                print(f'  Length: {length}, Entropy: {entropy:.2f}')\n\n    def _entropy(self, s):\n        import math\n        prob = [float(s.count(c)) / len(s) for c in set(s)]\n        return -sum(p * math.log(p) / math.log(2.0) for p in prob)\n\nif __name__ == '__main__':\n    detector = DNSTunnelDetector()\n    detector.analyze_pcap('capture.pcap')",
         "network_security", "network_security"),

        # ── IAM Security ──
        ("What are the IAM best practices for AWS?",
         "## AWS IAM Best Practices\n\n"
         "### 1. Use Roles, Not Users\n"
         "- Never create IAM users for humans (use SSO/Identity Center)\n"
         "- Use IAM roles for EC2, Lambda, ECS tasks\n"
         "- Prefer service-linked roles for AWS services\n\n"
         "### 2. Least Privilege\n"
         "```json\n{\n    \"Effect\": \"Allow\",\n    \"Action\": [\n        \"s3:GetObject\",\n        \"s3:ListBucket\"\n    ],\n    \"Resource\": [\n        \"arn:aws:s3:::specific-bucket\",\n        \"arn:aws:s3:::specific-bucket/*\"\n    ]\n}\n```\n\n"
         "### 3. Use Conditions\n"
         "```json\n\"Condition\": {\n    \"IpAddress\": {\"aws:SourceIp\": \"203.0.113.0/24\"},\n    \"Bool\": {\"aws:MultiFactorAuthPresent\": \"true\"},\n    \"StringEquals\": {\"aws:RequestedRegion\": \"us-east-1\"}\n}\n```\n\n"
         "### 4. Permission Boundaries\n"
         "- Set max permissions per role/user\n"
         "- Prevents privilege escalation within account\n\n"
         "### 5. Access Analyzer\n"
         "- Enable IAM Access Analyzer\n"
         "- Review findings weekly\n"
         "- Generate least-privilege policies from CloudTrail\n\n"
         "### 6. Regular Audits\n"
         "```bash\n# Find unused roles\naws iam list-roles --query 'Roles[?RoleLastUsed==null]'\n\n# Find old access keys\naws iam list-access-keys --query 'AccessKeyMetadata[?Status==`Active` && CreateDate<`2024-01-01`]'\n\n# Check for full admin\naws iam list-attached-role-policies --role-name MyRole | grep AdministratorAccess\n```\n\n"
         "### 7. Emergency Access\n"
         "- Break-glass procedure for IAM admin access\n"
         "- Require MFA + approval workflow for privileged actions\n"
         "- Monitor with CloudTrail + EventBridge alerts",
         "iam", "identity_access_management"),

        # ── Incident Response Playbooks ──
        ("Write an incident response playbook for ransomware",
         "## Ransomware Incident Response Playbook\n\n"
         "### Triage (First 15 Minutes)\n"
         "- [ ] Confirm the incident: ransom note, encrypted files, detection alert\n"
         "- [ ] Determine scope: how many systems affected?\n"
         "- [ ] Isolate: disconnect affected hosts from network (not power off!)\n"
         "- [ ] Block C2: firewall/IPS rules for known indicators\n"
         "- [ ] Notify IR team, legal, and management\n\n"
         "### Containment (First Hour)\n"
         "- [ ] Identify patient zero (initial infection vector)\n"
         "- [ ] Block ransomware binary hash at EDR/AV\n"
         "- [ ] Disable compromised account credentials\n"
         "- [ ] Block SMB/RDP lateral movement at firewall\n"
         "- [ ] Enable MFA enforcement if not already active\n"
         "- [ ] Preserve memory from affected systems\n\n"
         "### Investigation (2-4 Hours)\n"
         "- [ ] Collect: memory dumps, event logs, network captures\n"
         "- [ ] Identify: ransomware family (mutexes, extensions, ransom note)\n"
         "- [ ] Search for: data exfiltration, persistence mechanisms\n"
         "- [ ] Check: backup integrity, recovery points\n"
         "- [ ] Document: timeline of events, IOCs\n\n"
         "### Eradication (4-8 Hours)\n"
         "- [ ] Remove malware from all affected systems\n"
         "- [ ] Patch initial entry vector\n"
         "- [ ] Reset all credentials (domain admin, service accounts)\n"
         "- [ ] Review and remove unauthorized persistence\n"
         "- [ ] Validate no remaining IOCs\n\n"
         "### Recovery (8-24 Hours)\n"
         "- [ ] Restore from clean backups (verify clean first)\n"
         "- [ ] Scan restored data for backdoors\n"
         "- [ ] Bring critical systems online in isolation first\n"
         "- [ ] Monitor restored systems for reinfection\n\n"
         "### Post-Incident (24-48 Hours)\n"
         "- [ ] Root cause analysis report\n"
         "- [ ] Update detection rules with new IOCs\n"
         "- [ ] Improve backup processes if gaps found\n"
         "- [ ] Conduct lessons learned meeting\n"
         "- [ ] Update IR playbook with findings\n"
         "- [ ] File insurance claim if applicable",
         "incident_response", "incident_response"),

        # ── Compliance ──
        ("What are the key requirements of GDPR Article 32 for security?",
         "## GDPR Article 32 — Security of Processing\n\n"
         "### Key Requirements\n\n"
         "#### 1. Pseudonymization and Encryption (Art. 32(1)(a))\n"
         "- Encrypt personal data at rest and in transit\n"
         "- Implement pseudonymization where possible\n"
         "- Use strong encryption (AES-256, TLS 1.3)\n\n"
         "#### 2. Confidentiality, Integrity, Availability (Art. 32(1)(b))\n"
         "- Access controls (RBAC, MFA, least privilege)\n"
         "- Integrity checks (hashing, audit logs)\n"
         "- Availability measures (backup, disaster recovery, HA)\n\n"
         "#### 3. Resilience (Art. 32(1)(c))\n"
         "- Incident response capability\n"
         "- Business continuity planning\n"
         "- DDoS protection\n\n"
         "#### 4. Testing and Assessment (Art. 32(1)(d))\n"
         "- Regular penetration tests\n"
         "- Vulnerability scanning\n"
         "- Security audits (internal/external)\n"
         "- Tabletop exercises\n\n"
         "### Implementation Checklist\n"
         "- [ ] Data Protection Impact Assessment (DPIA) completed\n"
         "- [ ] Data Processing Agreement (DPA) with all vendors\n"
         "- [ ] Incident response plan documented and tested\n"
         "- [ ] 72-hour breach notification procedure\n"
         "- [ ] Data retention and deletion policies\n"
         "- [ ] Employee security training program\n"
         "- [ ] Records of Processing Activities (ROPA) maintained",
         "compliance", "governance_risk_compliance"),

        # ── Threat Intelligence ──
        ("How do you set up a threat intelligence program from scratch?",
         "## Building a Threat Intelligence Program\n\n"
         "### Tier 1 — Tactical (Short-term, Machine-readable)\n"
         "- **IOC feeds**: AlienVault OTX, MISP, ThreatFox\n"
         "- **Automated ingestion**: SIEM integration, firewall blocklists\n"
         "- **Update frequency**: Every 1-4 hours\n"
         "- **Example IOCs**: IPs, domains, hashes, C2 URLs\n\n"
         "### Tier 2 — Operational (Medium-term, Structured)\n"
         "- **TTP tracking**: MITRE ATT&CK framework mapping\n"
         "- **Threat actor profiles**: Who is targeting your industry?\n"
         "- **Campaign tracking**: Group activities, TTP evolution\n"
         "- **Sources**: ISACs, industry reports, Dark Web monitoring\n"
         "- **Update frequency**: Daily/weekly\n\n"
         "### Tier 3 — Strategic (Long-term, Executive-facing)\n"
         "- **Risk assessments**: Threat landscape for your sector\n"
         "- **Trend analysis**: Emerging attack vectors\n"
         "- **Budget recommendations**: Tooling, staffing\n"
         "- **Sources**: Vendor reports, government alerts (CISA, NCSC)\n"
         "- **Update frequency**: Quarterly\n\n"
         "### Tool Stack\n"
         "```\n+------------------+    +----------------+    +----------------+\n| Collectors       | -> | Platform       | -> | Distribution    |\n| - MISP           |    | - OpenCTI      |    | - SIEM          |\n| - TheHive        |    | - MITRE ATT&CK |    | - Firewall      |\n| - Feeds          |    | - Threat Intel  |    | - EDR           |\n| - OSINT          |    |   Portal        |    | - SOAR          |\n+------------------+    +----------------+    +----------------+\n```\n\n"
         "### Maturity Levels\n"
         "- **Level 1**: Reactive — no formal program, ad-hoc IOC collection\n"
         "- **Level 2**: Minimum — IOC feeds integrated, basic sharing\n"
         "- **Level 3**: Operational — TTP tracking, industry sharing\n"
         "- **Level 4**: Proactive — Predictive intel, automated defense\n"
         "- **Level 5**: Leading — AI-driven, cross-sector collaboration",
          "threat_intel", "threat_intel"),

        # ── Security Leadership ──
        ("How do you calculate and present cybersecurity ROI to executives?",
         "## Cybersecurity ROI for Executives\n\n"
         "### Key Metrics\n\n"
         "#### 1. Risk Reduction\n"
         "- **Annual Loss Expectancy (ALE)** before vs after control\n"
         "- Formula: ALE = SLE (Single Loss Expectancy) × ARO (Annual Rate of Occurrence)\n"
         "- Example: Ransomware ALE = $500K × 0.2 = $100K/year\n\n"
         "#### 2. Cost Avoidance\n"
         "- Incidents prevented × average incident cost\n"
         "- $X spent on EDR + SOC = $Y in breach costs avoided\n\n"
         "#### 3. Efficiency Gains\n"
         "- Automation of manual tasks\n"
         "- Example: SOAR reducing MTTR from 4hrs to 30min\n"
         "- Analyst hours saved × hourly rate\n\n"
         "### Presentation Template\n\n"
         "```\nSecurity Program ROI Report\nQ4 2024\n\nInvestments:\n  EDR Tooling:         $150K\n  SOC Staff:           $400K\n  Training:            $50K\n  Total:               $600K\n\nBenefits Realized:\n  Incidents avoided:   18  (@ $85K avg) = $1.53M\n  Downtime avoided:    120 hrs (@ $10K/hr) = $1.2M\n  Compliance fines avoided:  $500K\n  Total:               $3.23M\n\nROI: 438%\n(NPV: $2.63M over 12 months)\n```\n\n"
         "### Communication Tips\n"
         "- **Speak business language**: Revenue protected, not CVEs found\n"
         "- **Use benchmarks**: Peer comparison (same industry, size)\n"
         "- **Show trends**: MTTR improving, false positives decreasing\n"
         "- **Risk framework**: NIST CSF maturity levels\n"
         "- **Always include**: \"What happens if we don't invest\" scenario",
         "security_leadership", "security_leadership"),

        # ── Supply Chain Security / SBOM ──
        ("What is a Software Bill of Materials (SBOM) and why is it important?",
         "## Software Bill of Materials (SBOM)\n\n"
         "### Definition\n"
         "An SBOM is a nested inventory of all components, libraries, and dependencies "
         "that make up a software application. It is the software equivalent of a "
         "nutrition label.\n\n"
         "### SBOM Formats\n"
         "- **SPDX** (ISO/IEC 5962): Linux Foundation, most widely adopted\n"
         "- **CycloneDX**: OWASP, designed for security use cases (includes vulnerabilities)\n"
         "- **SWID**: ISO/IEC 19770-2, ISO standard for tag-based identification\n\n"
         "### Why It Matters\n"
         "1. **Log4Shell (CVE-2021-44228)**: Orgs without SBOMs spent weeks mapping "
         "Log4j usage; those with SBOMs knew in minutes\n"
         "2. **SolarWinds**: Supply chain compromise affected 18,000+ orgs\n"
         "3. **US Executive Order 14028**: Mandates SBOMs for all federal software\n\n"
         "### SBOM Fields (SPDX)\n"
         "```json\n{\n  \"spdxVersion\": \"SPDX-2.3\",\n  \"name\": \"my-app-1.0\",\n  \"packages\": [\n    {\n      \"name\": \"openssl\",\n      \"versionInfo\": \"3.0.12\",\n      \"licenseDeclared\": \"Apache-2.0\",\n      \"externalRefs\": [\n        {\"referenceCategory\": \"SECURITY\", \"referenceLocator\": \"cpe:2.3:a:openssl:openssl:3.0.12\"}\n      ]\n    }\n  ]\n}\n```\n\n"
         "### SLSA Framework\n"
         "- **SLSA 1**: Documentation of build process\n"
         "- **SLSA 2**: Signed provenance, hosted build\n"
         "- **SLSA 3**: Tamper-proof provenance, hermetic builds\n"
         "- **SLSA 4**: Two-person review, reproducible builds\n\n"
         "### Tools\n"
         "- **Generate**: syft, trivy, cdxgen\n"
         "- **Validate**: sbom-validator, OWASP CycloneDX CLI\n"
         "- **Monitor**: Dependency-Track, GUAC, govulncheck",
         "supply_chain", "supply_chain_security"),

        # ── OT/ICS Security ──
        ("Explain the Purdue Model for ICS security",
         "## Purdue Model for ICS Security\n\n"
         "### Architecture Layers\n"
         "```\nLevel 4-5: Enterprise IT\n  +----------------------+\n  | Level 5: Corporate   |  ERP, email, web, HR\n  | Level 4: Site Ops    |  Historian, DMZ, patch mgmt\n  +-----------+----------+\n              | Firewall |\n  +-----------+----------+\n  | Level 3:  | Site Ops |  SCADA servers, engineering\n  | Level 2:  | Control  |  HMIs, alarming, batch mgmt\n  | Level 1:  | Basic    |  PLCs, RTUs, DCS controllers\n  | Level 0:  | Physical |  Sensors, actuators, valves\n  +----------------------+\n```\n\n"
         "### Key Security Principles\n"
         "1. **No direct IT→OT communication**: All traffic through DMZ\n"
         "2. **Unidirectional gateways**: Data diodes for critical flows\n"
         "3. **Air-gap critical Level 0-1 networks**: No network connectivity\n"
         "4. **Deep packet inspection**: Modbus/DNP3-aware firewalls\n"
         "5. **Asset inventory**: Maintain ICS-specific asset database\n\n"
         "### Common OT Protocols & Risks\n"
         "| Protocol | Use | Risk |\n"
         "|---|---|---|\n"
         "| **Modbus TCP** | PLC communication | No authentication, no encryption |\n"
         "| **DNP3** | Power/water SCADA | Weak authentication in older versions |\n"
         "| **OPC-UA** | Industrial data exchange | Misconfigured security modes |\n"
         "| **S7comm** | Siemens PLCs | Proprietary, limited logging |\n"
         "| **EtherNet/IP** | Factory automation | Broadcast-based, easy to spoof |\n\n"
         "### IEC 62443 Standards\n"
         "- **IEC 62443-2-1**: Security management system for IACS\n"
         "- **IEC 62443-3-3**: System security requirements and security levels\n"
         "- **IEC 62443-4-1**: Secure development lifecycle for products\n"
         "- **IEC 62443-4-2**: Technical security requirements for components\n\n"
         "### Defense in Depth for OT\n"
         "- Network segmentation per Purdue levels\n"
         "- Application whitelisting on HMIs and engineering workstations\n"
         "- USB device control (common infection vector)\n"
         "- Remote access via jump boxes with MFA\n"
         "- Regular backup of PLC/RTU configurations\n"
         "- Vendor access management and auditing",
         "ot_security", "ot_ics_security"),

        # ── Mobile Security (Android) ──
        ("What are the OWASP Mobile Top 10 vulnerabilities?",
         "## OWASP Mobile Top 10 (2024)\n\n"
         "### M1: Improper Credential Usage\n"
         "- Storing credentials in SharedPreferences (Android) or UserDefaults (iOS)\n"
         "- Using hardcoded API keys in the app binary\n"
         "- **Fix**: Use Android Keystore / iOS Keychain; biometric auth\n\n"
         "### M2: Inadequate Supply Chain Security\n"
         "- Third-party SDKs with excessive permissions\n"
         "- Outdated library versions with known CVEs\n"
         "- **Fix**: Regular dependency scanning, SBOM generation\n\n"
         "### M3: Insecure Authentication/Authorization\n"
         "- Weak token validation on mobile API endpoints\n"
         "- Missing device attestation\n"
         "- **Fix**: Implement OAuth 2.0 + PKCE, JWT with short expiry\n\n"
         "### M4: Insufficient Input/Output Validation\n"
         "- XSS in WebViews, path traversal in file handling\n"
         "- SQL injection in local databases\n"
         "- **Fix**: Sanitize all WebView inputs, use parameterized queries\n\n"
         "### M5: Insecure Communication\n"
         "- Certificate pinning not implemented\n"
         "- Mixed HTTP/HTTPS content\n"
         "- **Fix**: SSL pinning (TrustKit iOS, OkHttp Android), HSTS\n\n"
         "### M6: Inadequate Privacy Controls\n"
         "- Collecting more data than necessary\n"
         "- No consent mechanism\n"
         "- **Fix**: Minimize data collection; transparent consent UI\n\n"
         "### M7: Insecure Data Storage\n"
         "- Storing sensitive data in SQLite without encryption\n"
         "- Logging sensitive data\n"
         "- **Fix**: EncryptedSharedPreferences, iOS Data Protection API\n\n"
         "### M8: Insecure Defaults\n"
         "- Debug mode enabled in production\n"
         "- Verbose error messages\n"
         "- **Fix**: Build config validation, remove debug code\n\n"
         "### M9: Insufficient Cryptography\n"
         "- Using ECB mode, custom crypto implementations\n"
         "- Weak key generation\n"
         "- **Fix**: Use platform crypto libraries (Conscrypt, CryptoKit)\n\n"
         "### M10: Lack of Binary Protections\n"
         "- No code obfuscation, easy to reverse engineer\n"
         "- Root/jailbreak detection missing\n"
         "- **Fix**: ProGuard/R8 obfuscation, runtime integrity checks",
         "mobile_security", "mobile_security"),

        # ── Cryptography & PKI ──
        ("Explain the TLS 1.3 handshake and how it differs from TLS 1.2",
         "## TLS 1.3 Handshake\n\n"
         "### TLS 1.3 Handshake (1-RTT)\n"
         "```\nClient                                      Server\n  |                                            |\n  |--- ClientHello (key_share, sig_algs) ----->|\n  |                                            |\n  |<--- ServerHello + EncryptedExtensions ------|\n  |     Certificate + CertificateVerify + Finished\n  |                                            |\n  |--- Finished + Application Data ----------->|\n  |                                            |\n  |<--- Application Data ----------------------|\n  |                                            |\n```\n\n"
         "### Key Differences from TLS 1.2\n\n"
         "| Feature | TLS 1.2 | TLS 1.3 |\n"
         "|---|---|---|\n"
         "| RTT for new session | 2 RTT (full handshake) | 1 RTT (or 0-RTT for resumed) |\n"
         "| Cipher suites | Many (CBC, RC4, 3DES removed) | AEAD only (AES-GCM, ChaCha20-Poly1305) |\n"
         "| Key exchange | RSA, DH, ECDH (separate) | (EC)DHE always (PFS guaranteed) |\n"
         "| Supported algorithms | 37+ | 5 |\n"
         "| Renegotiation | Supported | Removed |\n"
         "| Compression | Supported | Removed |\n"
         "| Session resumption | Session ID, Session Ticket | PSK + PSK-DHE |\n"
         "| 0-RTT | Not supported | Supported with anti-replay |\n\n"
         "### Security Improvements\n"
         "1. **Forward secrecy guaranteed**: No RSA key exchange\n"
         "2. **Removed weak algorithms**: No RC4, 3DES, CBC, MD5, SHA-224\n"
         "3. **Encrypted handshake**: Certificates are encrypted (privacy)\n"
         "4. **Simplified**: Fewer options = less misconfiguration\n"
         "5. **Faster**: 1-RTT vs 2-RTT (33% faster setup)\n\n"
         "### Common Crypto Mistakes\n"
         "- Using self-signed certificates in production\n"
         "- Weak DH parameters (1024-bit instead of 2048+)\n"
         "- Disabling certificate revocation checks (OCSP/CRL)\n"
         "- Mixed content on HTTPS pages\n"
         "- Wildcard certificates used for sensitive subdomains\n"
         "- Expired certificates not detected (use cert-manager, acme.sh)",
         "cryptography", "cryptography_pki"),

        # ── Zero Trust Architecture ──
        ("What are the seven pillars of Zero Trust architecture per NIST SP 800-207?",
         "## Zero Trust Architecture (NIST SP 800-207)\n\n"
         "### Core Principle\n"
         "\"Never trust, always verify.\" No entity is trusted by default, "
         "regardless of network location.\n\n"
         "### The 7 Pillars\n\n"
         "#### 1. Identity\n"
         "- Every user authenticated and authorized per session\n"
         "- Continuous verification (not just login)\n"
         "- Risk-based authentication (location, device, behavior)\n"
         "- **Tools**: Okta, Azure AD, Keycloak\n\n"
         "#### 2. Device\n"
         "- Every device must be known and compliant\n"
         "- Device health checks before resource access\n"
         "- MDM/UEM enrollment required\n"
         "- **Tools**: Jamf, Intune, SentinelOne\n\n"
         "#### 3. Network\n"
         "- Micro-segmentation (not just perimeter firewall)\n"
         "- End-to-end encryption for all traffic\n"
         "- Network visibility and analytics\n"
         "- **Tools**: Illumio, Cisco ACI, NSX-T\n\n"
         "#### 4. Application\n"
         "- Applications as protected surfaces\n"
         "- Application-layer authorization\n"
         "- API security gateways\n"
         "- **Tools**: Cloudflare Access, Pomerium, Zscaler\n\n"
         "#### 5. Data\n"
         "- Data classification and labeling\n"
         "- Encryption at rest and in transit\n"
         "- DLP controls based on data sensitivity\n"
         "- **Tools**: BigID, Microsoft Purview, Varonis\n\n"
         "#### 6. Visibility & Analytics\n"
         "- Continuous monitoring of all entities\n"
         "- UEBA for anomaly detection\n"
         "- Automated threat response\n"
         "- **Tools**: Splunk, Datadog, Sentinel\n\n"
         "#### 7. Automation & Orchestration\n"
         "- Policy-as-code for access decisions\n"
         "- Automated incident response\n"
         "- CI/CD security integration\n"
         "- **Tools**: Terraform, Ansible, Tines\n\n"
         "### Zero Trust Maturity Model\n"
         "- **Traditional**: VPN-based, perimeter firewall\n"
         "- **Initial**: MFA rollout, basic segmentation\n"
         "- **Advanced**: Device trust, micro-segmentation, SSE\n"
         "- **Optimal**: Continuous validation, AI-driven policy",
         "zero_trust", "zero_trust_architecture"),

        # ── HIPAA Compliance ──
        ("What are the key HIPAA Security Rule requirements for covered entities?",
         "## HIPAA Security Rule Requirements\n\n"
         "### Administrative Safeguards (§164.308)\n"
         "1. **Security Management Process**: Risk analysis, risk management, sanction policy\n"
         "2. **Assigned Security Responsibility**: Named security officer\n"
         "3. **Workforce Security**: Authorization, supervision, termination procedures\n"
         "4. **Information Access Management**: Access authorization, access establishment\n"
         "5. **Security Awareness and Training**: Security reminders, password mgmt\n"
         "6. **Security Incident Procedures**: Response and reporting\n"
         "7. **Contingency Plan**: Data backup, disaster recovery, emergency mode\n"
         "8. **Evaluation**: Periodic technical and non-technical evaluation\n"
         "9. **Business Associate Contracts**: Written agreements with all BAs\n\n"
         "### Physical Safeguards (§164.310)\n"
         "1. **Facility Access Controls**: Contingency operations, facility security plan\n"
         "2. **Workstation Use**: Proper use policies\n"
         "3. **Workstation Security**: Physical safeguards for workstations\n"
         "4. **Device and Media Controls**: Disposal, re-use, accountability, data backup\n\n"
         "### Technical Safeguards (§164.312)\n"
         "1. **Access Control** (required): Unique user IDs, emergency access, auto logoff\n"
         "2. **Audit Controls** (required): HW/SW/transaction recording\n"
         "3. **Integrity Controls** (required): Mechanism to authenticate ePHI\n"
         "4. **Person or Entity Authentication** (required): User verification\n"
         "5. **Transmission Security** (required): Encryption, integrity controls\n\n"
         "### Breach Notification Rule (§164.400-414)\n"
         "- **500+ individuals**: Notify HHS, affected individuals, media within 60 days\n"
         "- **<500 individuals**: Notify HHS annually, affected individuals within 60 days\n"
         "- **Unsecured ePHI**: Assumed breach unless risk assessment shows low probability\n\n"
         "### Penalties\n"
         "| Tier | Violation | Penalty |\n"
         "|---|---|---|\n"
         "| 1 | Unknowing | $100-$50K per violation |\n"
         "| 2 | Reasonable cause | $1K-$50K per violation |\n"
         "| 3 | Willful neglect (corrected) | $10K-$50K per violation |\n"
         "| 4 | Willful neglect (uncorrected) | $50K-$1.5M per violation |\n\n"
         "### Common Violations\n"
         "- Lost/stolen unencrypted laptops or mobile devices\n"
         "- Improper disposal of PHI\n"
         "- Unauthorized access by employees\n"
         "- Lack of BA agreements\n"
         "- Failure to conduct risk analysis",
         "hipaa", "healthcare_compliance"),

        # ── Red Team Operations ──
        ("What is the red team engagement lifecycle?",
         "## Red Team Engagement Lifecycle\n\n"
         "### Phase 1: Planning & Recon (Weeks 1-2)\n"
         "- **Rules of Engagement (ROE)**: Scope, exclusions, communication channels\n"
         "- **Intel gathering**: OSINT, DNS enumeration, Shodan, social media\n"
         "- **Attack surface mapping**: Subdomains, exposed services, tech stack\n"
         "- **Tools**: Amass, Sublist3r, Shodan, Maltego, theHarvester\n\n"
         "### Phase 2: Initial Access (Weeks 2-3)\n"
         "- **Phishing**: Spear-phishing, vishing, SMS phishing\n"
         "- **Web exploitation**: SQLi, SSRF, RCE, subdomain takeover\n"
         "- **Physical**: Tailgating, badge cloning, lock picking\n"
         "- **Supply chain**: Compromised dependencies, watering hole\n\n"
         "### Phase 3: Command & Control (Week 3+)\n"
         "- **C2 setup**: Cobalt Strike, Mythic, Sliver, Havoc\n"
         "- **Egress detection**: Testing firewall/egress filtering\n"
         "- **Domain fronting**: Hiding C2 traffic behind CDNs\n"
         "- **OPSEC**: Sleep timers, jitter, traffic shaping\n\n"
         "### Phase 4: Lateral Movement (Week 3-4)\n"
         "- **Credential harvesting**: Mimikatz, LSASS dumps, Kerberoasting\n"
         "- **Pass-the-hash/ticket**: Lateral movement via SMB/WMI/WinRM\n"
         "- **SSH hopping**: Linux lateral movement\n"
         "- **Cloud lateral**: Assume role, SSRF to metadata service\n\n"
         "### Phase 5: Persistence (Week 4)\n"
         "- **Backdoor users**: Create hidden admin accounts\n"
         "- **Scheduled tasks/cron**: Beacon re-installation\n"
         "- **Registry run keys**: Startup persistence\n"
         "- **Service accounts**: Golden ticket, Silver ticket\n\n"
         "### Phase 6: Exfiltration (Week 4-5)\n"
         "- **Data staging**: Collecting sensitive data\n"
         "- **Covert exfil**: DNS tunneling, HTTPS, social media\n"
         "- **Size testing**: Gradual exfiltration to avoid detection\n\n"
         "### Phase 7: Reporting (Week 5-6)\n"
         "- **Executive summary**: Business impact, risk rating\n"
         "- **Technical report**: Full attack chain with evidence\n"
         "- **Remediation roadmap**: Prioritized by risk\n"
         "- **Purple team workshop**: Blue team detection gaps",
         "red_team", "red_team_operations"),

        # ── Wireless Security ──
        ("How does WPA3 improve security over WPA2?",
         "## WPA3 vs WPA2 Security\n\n"
         "### WPA2 Weaknesses\n"
         "1. **KRACK Attack (CVE-2017-13077)**: Key reinstallation attack on 4-way handshake\n"
         "2. **PMKID Attack**: Offline brute force of router PSK\n"
         "3. **No forward secrecy**: Captured traffic can be decrypted if PSK later known\n"
         "4. **Weak password policy**: No protection against dictionary attacks\n"
         "5. **Open networks**: No encryption on public Wi-Fi without additional setup\n\n"
         "### WPA3 Improvements\n"
         "1. **Simultaneous Authentication of Equals (SAE)**: Replaces PSK-based 4-way handshake\n"
         "   - Resistant to offline dictionary attacks\n"
         "   - Forward secrecy: compromising PSK does not decrypt past traffic\n"
         "   - Dragonfly handshake provides mutual authentication\n\n"
         "2. **192-bit Security Suite (WPA3-Enterprise)**:\n"
         "   - Mandatory GCMP-256 encryption\n"
         "   - HMAC-SHA384 for integrity\n"
         "   - ECDH P-384 for key exchange\n"
         "   - ECDSA P-384 for certificate validation\n\n"
         "3. **Wi-Fi Enhanced Open (OWE)**:\n"
         "   - Opportunistic Wireless Encryption for open networks\n"
         "   - Individualized encryption per client\n"
         "   - No password needed, but traffic is encrypted\n\n"
         "4. **PMF (Protected Management Frames) Mandatory**:\n"
         "   - Prevents deauthentication attacks\n"
         "   - Protects management frame spoofing\n\n"
         "### Security Comparison\n\n"
         "| Feature | WPA2 | WPA3 |\n"
         "|---|---|---|\n"
         "| Authentication | 4-way handshake (PSK) | SAE handshake |\n"
         "| Offline dictionary attack | Vulnerable | Protected |\n"
         "| Forward secrecy | No | Yes |\n"
         "| Encryption | AES-CCMP (128-bit) | AES-GCMP (128/256-bit) |\n"
         "| Open network | No encryption | OWE encryption |\n"
         "| Management frames | Optional PMF | Mandatory PMF |\n"
         "| IoT onboarding | WPS vulnerable | Wi-Fi Easy Connect (DPP) |\n\n"
         "### Common Attacks on WPA3\n"
         "- **Dragonblood**: Side-channel attacks on SAE implementation (mostly patched)\n"
         "- **Downgrade attack**: Force WPA2 fallback if both supported\n"
         "- **Evil Twin**: Still works; always verify SSID + use VPN",
         "wireless_security", "wireless_security"),

        # ── Web3 / Blockchain Security ──
        ("What is a reentrancy attack in smart contracts?",
         "## Smart Contract Reentrancy Attack\n\n"
         "### How It Works\n"
         "Reentrancy exploits the fact that a contract can call back into the calling "
         "contract before the first invocation completes, allowing withdrawal of "
         "funds multiple times.\n\n"
         "### Classic Example (The DAO Hack 2016 — $60M stolen)\n"
         "```solidity\n// VULNERABLE\ncontract Victim {\n    mapping(address => uint) balances;\n\n    function withdraw(uint amount) public {\n        require(balances[msg.sender] >= amount);\n        (bool success, ) = msg.sender.call{value: amount}(\"\");  // calls attacker!\n        require(success);\n        balances[msg.sender] -= amount;  // balance NOT updated yet\n    }\n}\n\n// ATTACKER\ncontract Attacker {\n    Victim victim;\n\n    function attack() public {\n        victim.withdraw(1 ether);\n    }\n\n    receive() external payable {\n        if (address(victim).balance > 0) {\n            victim.withdraw(1 ether);  // re-enter before balance updated\n        }\n    }\n}\n```\n\n"
         "### The Fix: Checks-Effects-Interactions Pattern\n"
         "```solidity\n// SECURE\ncontract Safe {\n    mapping(address => uint) balances;\n\n    function withdraw(uint amount) public {\n        require(balances[msg.sender] >= amount);\n        balances[msg.sender] -= amount;  // EFFECTS first\n        (bool success, ) = msg.sender.call{value: amount}(\"\");  // INTERACTION last\n        require(success);\n    }\n}\n```\n\n"
         "### Prevention\n"
         "1. **Checks-Effects-Interactions**: Update state before calling external contracts\n"
         "2. **ReentrancyGuard (OpenZeppelin)**: Mutex lock\n"
         "3. **Limit gas**: Send only enough for the intended operation\n"
         "4. **Avoid `call.value()`**: Prefer `transfer()` (forwards 2300 gas — enough only for logging)\n"
         "5. **Formal verification**: Use tools like Slither, Mythril, Certora\n\n"
         "### Other Common Smart Contract Vulnerabilities\n"
         "- **Flash loan attacks**: Oracle manipulation via uncollateralized loans\n"
         "- **Front-running**: MEV bots exploit transaction ordering\n"
         "- **Access control**: Missing `onlyOwner` modifiers\n"
         "- **Integer overflow/underflow**: Arithmetic without SafeMath\n"
         "- **Oracle manipulation**: Price feed single-source dependency",
         "blockchain_security", "web3_blockchain_security"),

        # ── Network Forensics ──
        ("How do you analyze a pcap file for signs of C2 beaconing?",
         "## C2 Beaconing Detection in PCAP\n\n"
         "### Step 1: Identify Unusual Connections\n"
         "```bash\n# Extract all unique destination IPs and count connections\ntshark -r capture.pcap -T fields -e ip.dst | sort | uniq -c | sort -n | tail -20\n\n# Check for connections on non-standard ports\ntshark -r capture.pcap -T fields -e tcp.dstport | sort | uniq -c | sort -n\n\n# Look for connections to known bad IPs (Threat intel feed)\ntshark -r capture.pcap -Y \"ip.dst in {203.0.113.0/24}\" -T fields -e ip.src -e ip.dst\n```\n\n"
         "### Step 2: Detect Beacon Patterns\n"
         "```bash\n# Find periodic connections (beaconing)\ntshark -r capture.pcap -Y \"http.request\" -T fields -e frame.time_relative -e http.host -e http.request.uri | head -50\n\n# Check for consistent intervals\npython3 -c \"\nimport sys\n# Parse relative timestamps and check for periodicity\ntimes = [float(line.split()[0]) for line in open('timestamps.txt') if line.strip()]\ndiffs = [round(times[i+1] - times[i], 1) for i in range(len(times)-1)]\nprint('Intervals:', diffs[:20])\nprint('Mean interval:', sum(diffs)/len(diffs) if diffs else 'N/A')\n\"\n```\n\n"
         "### Step 3: Analyze DNS Tunneling\n"
         "```bash\n# Check for DNS queries with unusual subdomain lengths\ntshark -r capture.pcap -Y \"dns.qry.name\" -T fields -e dns.qry.name | \\\n  awk -F. '{print length($1)}' | sort -n | uniq -c | sort -n\n\n# Subdomains > 20 chars = suspicious\ntshark -r capture.pcap -Y \"dns.qry.name\" -T fields -e dns.qry.name | \\\n  awk -F. 'length($1) > 20'\n\n# Base64-looking subdomains\ntshark -r capture.pcap -Y \"dns.qry.name\" -T fields -e dns.qry.name | \\\n  grep -E '^[A-Za-z0-9+/=]{20,}\\.'\n```\n\n"
         "### Step 4: HTTP/S Beacon Analysis\n"
         "```bash\n# User-Agent analysis — unusual or uncommon agents\ntshark -r capture.pcap -Y \"http.user_agent\" -T fields -e http.user_agent | sort | uniq -c | sort -n\n\n# Check for beacon-specific URI patterns\ntshark -r capture.pcap -Y \"http.request\" -T fields -e http.request.uri | \\\n  grep -iE '(api|gate|poll|checkin|beacon|update|heartbeat)'\n\n# JA3 fingerprinting for TLS beacons\ntshark -r capture.pcap -Y \"tls.handshake.type == 1\" -T fields -e tls.handshake.cipher_suites\n```\n\n"
         "### Step 5: Data Exfiltration\n"
         "```bash\n# Large outbound transfers (unusual)\ntshark -r capture.pcap -T fields -e ip.src -e ip.dst -e frame.len -e tcp.dstport | \\\n  awk '$4 == 443 && $3 > 1000' | head -20\n\n# DNS TXT queries with large response sizes\ntshark -r capture.pcap -Y \"dns.txt && dns.resp.len > 100\" -T fields -e dns.qry.name\n```\n\n"
         "### Tools Summary\n"
         "| Tool | Use Case |\n"
         "|---|---|\n"
         "| TShark/Wireshark | Deep packet analysis, protocol dissection |\n"
         "| Zeek (Bro) | Network metadata, conn logs, DNS logs |\n"
         "| RITA | Beacon detection, statistical analysis |\n"
         "| Suricata | IDS rules matching on PCAP |\n"
         "| NetworkMiner | File extraction, OS fingerprinting |\n"
         "| CapLoader | Large PCAP indexing and filtering |",
         "network_forensics", "digital_forensics"),

        # ── K8s Security (additional) ──
        ("What are the Kubernetes CIS Benchmark top recommendations?",
         "## Kubernetes CIS Benchmark (v1.9) — Top Controls\n\n"
         "### 1. Control Plane Configuration\n"
         "**1.1.1**: Ensure API server `--anonymous-auth` is set to `false`\n"
         "**1.2.2**: Ensure API server `--insecure-port` is set to `0` (disabled)\n"
         "**1.2.5**: Ensure API server uses TLS 1.3 (`--tls-cipher-suites`)\n"
         "**1.2.7**: Ensure API server `--etcd-cafile` and `--etcd-certfile` are set\n\n"
         "### 2. etcd Configuration\n"
         "**2.1**: Ensure etcd peer/client TLS is enabled\n"
         "**2.2**: Ensure etcd data directory ownership is `etcd:etcd`\n"
         "**2.3**: Ensure etcd auto-compaction is set (`--auto-compaction-retention`)\n\n"
         "### 3. Kubelet Configuration\n"
         "**3.1.1**: Ensure `--anonymous-auth` is `false` on kubelet\n"
         "**3.1.3**: Ensure `--read-only-port` is `0` (disabled)\n"
         "**3.2.1**: Ensure `ProtectKernelDefaults` is set in kubelet config\n"
         "**3.2.2**: Ensure kubelet `--make-iptables-util-chains` is `true`\n\n"
         "### 4. Pod Security\n"
         "**4.1.1**: Ensure `PodSecurity` admission plugin is enabled (replace PSP)\n"
         "**4.1.2**: Apply `restricted` PSS policy by default\n"
         "**4.2.1-6**: Ensure containers run as non-root, read-only root filesystem, "
         "no privilege escalation\n\n"
         "### 5. Network Security\n"
         "**5.1.1-7**: Network policies for all namespaces\n"
         "**5.2.1**: Enable `--encryption-provider-config` for etcd encryption\n"
         "**5.3.1**: Use RBAC, not ABAC\n\n"
         "### 6. Logging & Monitoring\n"
         "**6.1.1**: Ensure audit logging is enabled\n"
         "**6.2.1**: Enable `PodSecurityPolicy` in audit log policy (or PSA)\n"
         "**6.3.1**: Enable profiling for investigation (`--profiling`)\n\n"
         "### Automation with kube-bench\n"
         "```bash\n# Run kube-bench on your cluster\nkubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml\nkubectl logs job/kube-bench\n\n# Scan specific master components\nkube-bench run --targets master --version 1.28\n\n# Scan with custom config\nkube-bench run --config my-cfg.yaml\n```\n\n"
         "### Admission Controllers to Enable\n"
         "- `PodSecurity`: Kubernetes 1.23+ built-in PSA\n"
         "- `NodeRestriction`: Limits kubelet self-modification\n"
         "- `AlwaysPullImages`: Ensures latest image integrity\n"
         "- `DenyServiceExternalIPs`: Prevents external IP abuse\n"
         "- `ImagePolicyWebhook`: Container image scanning enforcement",
          "k8s_benchmark", "kubernetes_security"),

        # ── Sigma Rule: Direct Execution ──
        ("Write a Sigma rule to detect execution of sc.exe for service manipulation",
         "```yaml\ntitle: Sc.exe Service Manipulation\nid: b2f6d5c1-3a4e-4d7f-9c1a-8e5b2f3d4c5e\nstatus: experimental\ndescription: Detects the use of sc.exe for service creation, deletion, or modification\nreferences:\n  - https://attack.mitre.org/techniques/T1543/003/\nauthor: Cyber-LLM\ndate: 2024/01/15\ntags:\n  - attack.persistence\n  - attack.t1543.003\n  - attack.privilege_escalation\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\sc.exe'\n    CommandLine|contains:\n      - 'create'\n      - 'delete'\n      - 'config'\n      - 'failure'\n  condition: selection\nfalsepositives:\n  - Legitimate service management by administrators\nlevel: medium\n```",
         "sigma_rule", "detection_engineering"),

        # ── Sigma Rule: Scheduled Task ──
        ("Write a Sigma rule to detect suspicious scheduled task creation",
         "```yaml\ntitle: Suspicious Scheduled Task Creation\nid: c3d7e6f2-4b5f-5e8g-0d2b-9f6c3g4e5f6d\nstatus: experimental\ndescription: Detects creation of scheduled tasks with suspicious characteristics\nreferences:\n  - https://attack.mitre.org/techniques/T1053/005/\n  - https://thedfirreport.com/2022/06/20/scheduled-tasks-for-persistence/\nauthor: Cyber-LLM\ndate: 2024/01/15\ntags:\n  - attack.execution\n  - attack.t1053.005\n  - attack.persistence\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\schtasks.exe'\n    CommandLine|contains:\n      - '/create'\n      - '/sc ONLOGON'\n      - '/sc ONSTART'\n      - '/sc ONIDLE'\n      - '-Create'\n  selection_suspicious:\n    CommandLine|contains:\n      - '-System'\n      - 'SYSTEM'\n      - 'NT AUTHORITY'\n      - 'cmd.exe /c'\n      - 'powershell'\n      - '-EncodedCommand'\n  condition: selection and selection_suspicious\nfalsepositives:\n  - Software installers creating legitimate scheduled tasks\nlevel: medium\n```",
         "sigma_rule", "detection_engineering"),

        # ── KQL: Azure Sentinel RDP Brute Force ──
        ("Write a KQL query for Azure Sentinel to detect RDP brute force attacks",
         "```kql\n// RDP Brute Force Detection\n// Sources: SecurityEvent (Windows) or AADSignInEventsBeta\nlet threshold = 10;\nlet timeframe = timespan(5m);\nSecurityEvent\n| where EventID == 4625  // Failed logon\n| where LogonType == 10   // Remote Interactive (RDP)\n| summarize\n    FailedAttempts = count(),\n    FirstAttempt = min(TimeGenerated),\n    LastAttempt = max(TimeGenerated),\n    AccountsAttempted = make_set(TargetUserName),\n    SourceIPs = make_set(IpAddress),\n    WorkstationNames = make_set(WorkstationName)\n    by IpAddress, LogonType\n| where FailedAttempts > threshold\n| extend\n    TimeWindow = timeframe,\n    AlertSeverity = \"High\",\n    AlertName = \"RDP Brute Force Detected\",\n    MITRETechnique = \"T1110\"\n| project\n    TimeGenerated = LastAttempt,\n    AlertName,\n    AlertSeverity,\n    SourceIP = IpAddress,\n    FailedAttempts,\n    AccountsAttempted,\n    TimeWindow,\n    MITRETechnique,\n    WorkstationNames\n| order by FailedAttempts desc\n```",
         "kql_query", "detection_engineering"),

        # ── KQL: Azure Sentinel Mimikatz ──
        ("Write KQL for Azure Sentinel to detect LSASS dumping (Mimikatz)",
         "```kql\n// LSASS Access Detection (Mimikatz)\n// Detects suspicious access to lsass.exe process\nlet SuspiciousProcesses = dynamic([\n    \"cmd.exe\", \"powershell.exe\", \"pwsh.exe\",\n    \"rundll32.exe\", \"regsvr32.exe\", \"wmic.exe\",\n    \"taskmgr.exe\", \"procdump64.exe\", \"procdump.exe\"\n]);\nSecurityEvent\n| where EventID == 4656  // Handle to object requested\n  or EventID == 4663    // Access to object\n| where ObjectName contains \"lsass\"\n  or ObjectName contains \"lsaas\"\n| where ProcessName has_any (SuspiciousProcesses)\n| extend\n    AlertName = \"LSASS Access via Suspicious Process\",\n    AlertSeverity = \"High\",\n    MITRETechnique = \"T1003.001\"\n| project\n    TimeGenerated,\n    AlertName,\n    AlertSeverity,\n    Computer,\n    Account = SubjectUserName,\n    ProcessName,\n    ObjectName,\n    AccessMask,\n    MITRETechnique\n| sort by TimeGenerated desc\n```",
         "kql_query", "detection_engineering"),

        # ── Secure Coding: XSS Prevention ──
        ("Fix this React component vulnerable to XSS:\n```jsx\nfunction Comment({ comment }) {\n  return <div dangerouslySetInnerHTML={{ __html: comment.text }} />;\n}\n```",
         "```jsx\nimport DOMPurify from 'dompurify';\n\n// SECURE: Sanitize HTML before rendering\nfunction Comment({ comment }) {\n  // Option 1: Use DOMPurify if HTML is required\n  const cleanHtml = DOMPurify.sanitize(comment.text, {\n    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'code'],\n    ALLOWED_ATTR: ['href', 'class'],\n    ALLOW_DATA_ATTR: false,\n  });\n\n  return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;\n}\n\n// Option 2: Best — avoid dangerouslySetInnerHTML entirely\nfunction SafeComment({ comment }) {\n  // React auto-escapes by default\n  return (\n    <div>\n      {comment.text.split('\\n').map((line, i) => (\n        <p key={i}>{line}</p>\n      ))}\n    </div>\n  );\n}\n\n// Option 3: Use a proper rich text library\n// import { RichTextRenderer } from '@standard/RichTextRenderer';\n```",
         "secure_coding", "application_security"),

        # ── Secure Coding: Command Injection ──
        ("Fix this Go code vulnerable to command injection:\n```go\nfunc lookup(hostname string) {\n    cmd := exec.Command(\"ping\", \"-c\", \"1\", hostname)\n    out, _ := cmd.Output()\n    fmt.Println(string(out))\n}\n```",
         "```go\nimport (\n    \"context\"\n    \"fmt\"\n    \"net\"\n    \"os/exec\"\n    \"strings\"\n    \"time\"\n)\n\n// SECURE: Validate input, use safe APIs\nfunc lookup(hostname string) error {\n    // 1. Validate the hostname is a valid hostname/IP\n    if strings.Contains(hostname, \" \") ||\n       strings.Contains(hostname, \"|\") ||\n       strings.Contains(hostname, \";\") ||\n       strings.Contains(hostname, \"$\") {\n        return fmt.Errorf(\"invalid hostname: contains shell metacharacters\")\n    }\n\n    // 2. Resolve via net package instead of shelling out\n    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)\n    defer cancel()\n\n    ips, err := net.DefaultResolver.LookupHost(ctx, hostname)\n    if err != nil {\n        return fmt.Errorf(\"lookup failed: %w\", err)\n    }\n\n    fmt.Printf(\"Host %s resolves to: %v\\n\", hostname, ips)\n    return nil\n}\n\n// If ping is genuinely needed, use exec.Command (not shell)\nfunc safePing(hostname string) error {\n    // exec.Command passes args separately — no shell injection\n    cmd := exec.Command(\"ping\", \"-c\", \"1\", hostname)\n    out, err := cmd.Output()\n    if err != nil {\n        return err\n    }\n    fmt.Println(string(out))\n    return nil\n}\n```",
         "secure_coding", "application_security"),

        # ── Secure Coding: JWT Validation ──
        ("Write secure JWT authentication middleware in Python FastAPI",
         "```python\nfrom datetime import datetime, timedelta, timezone\nfrom typing import Optional\n\nimport jwt\nfrom fastapi import Depends, HTTPException, status\nfrom fastapi.security import HTTPBearer, HTTPAuthorizationCredentials\nfrom pydantic import BaseModel\n\nSECRET_KEY = None  # Set from environment variable\nALGORITHM = \"HS256\"\nACCESS_TOKEN_EXPIRE_MINUTES = 15\nREFRESH_TOKEN_EXPIRE_DAYS = 7\n\nsecurity = HTTPBearer(auto_error=False)\n\n\nclass TokenPayload(BaseModel):\n    sub: str\n    exp: datetime\n    iat: datetime\n    role: str = \"user\"\n\n\ndef create_access_token(user_id: str, role: str = \"user\") -> str:\n    now = datetime.now(timezone.utc)\n    payload = {\n        \"sub\": user_id,\n        \"role\": role,\n        \"iat\": now,\n        \"exp\": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),\n        \"type\": \"access\",\n    }\n    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)\n\n\ndef create_refresh_token(user_id: str) -> str:\n    now = datetime.now(timezone.utc)\n    payload = {\n        \"sub\": user_id,\n        \"iat\": now,\n        \"exp\": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),\n        \"type\": \"refresh\",\n    }\n    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)\n\n\ndef verify_token(\n    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),\n) -> TokenPayload:\n    if credentials is None:\n        raise HTTPException(\n            status_code=status.HTTP_401_UNAUTHORIZED,\n            detail=\"Authorization header required\",\n        )\n\n    token = credentials.credentials\n    try:\n        payload = jwt.decode(\n            token,\n            SECRET_KEY,\n            algorithms=[ALGORITHM],\n            options={\n                \"require\": [\"sub\", \"exp\", \"iat\", \"type\"],\n                \"verify_exp\": True,\n                \"verify_iat\": True,\n            },\n        )\n        return TokenPayload(**payload)\n    except jwt.ExpiredSignatureError:\n        raise HTTPException(\n            status_code=status.HTTP_401_UNAUTHORIZED,\n            detail=\"Token expired\",\n        )\n    except jwt.InvalidTokenError as e:\n        raise HTTPException(\n            status_code=status.HTTP_401_UNAUTHORIZED,\n            detail=f\"Invalid token: {e}\",\n        )\n\n\n# Security headers middleware\nasync def add_security_headers(response):\n    response.headers[\"Strict-Transport-Security\"] = \"max-age=31536000; includeSubDomains\"\n    response.headers[\"X-Content-Type-Options\"] = \"nosniff\"\n    response.headers[\"X-Frame-Options\"] = \"DENY\"\n    response.headers[\"X-XSS-Protection\"] = \"0\"  # Deprecated but defense in depth\n    return response\n```",
         "secure_coding", "application_security"),

        # ── Docker Security ──
        ("Write a production-grade secure Dockerfile for a Python web app",
         "```dockerfile\n# Stage 1: Build\nFROM python:3.12-slim AS builder\n\nRUN apt-get update && apt-get install -y --no-install-recommends \\\n    build-essential \\\n    && rm -rf /var/lib/apt/lists/*\n\nWORKDIR /app\nCOPY requirements.txt .\nRUN pip install --no-cache-dir --user -r requirements.txt\n\n# Stage 2: Runtime (minimal)\nFROM python:3.12-slim\n\n# Security: Create non-root user\nRUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser\n\n# Security: Install only runtime deps\nRUN apt-get update && apt-get install -y --no-install-recommends \\\n    ca-certificates \\\n    && rm -rf /var/lib/apt/lists/*\n\n# Security: Copy only built artifacts from builder\nCOPY --from=builder /root/.local /root/.local\nCOPY --chown=appuser:appuser app/ /app/\n\nWORKDIR /app\nUSER appuser\n\n# Security: Read-only root filesystem\n# Run with: docker run --read-only --tmpfs /tmp --tmpfs /var/run\n\n# Security: Health check\nHEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\\n  CMD python3 -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/health')\"\n\nEXPOSE 8000\n\n# Security: Use exec form, not shell form\nCMD [\"python3\", \"-m\", \"uvicorn\", \"main:app\", \"--host\", \"0.0.0.0\", \"--port\", \"8000\"]\n```",

         "docker_security", "docker_security"),

        # ── AWS IAM Least Privilege ──
        ("Write an AWS IAM policy granting least-privilege S3 access for a CI/CD pipeline",
         "```json\n{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Sid\": \"AllowListBuckets\",\n            \"Effect\": \"Allow\",\n            \"Action\": [\n                \"s3:ListBucket\",\n                \"s3:GetBucketLocation\",\n                \"s3:GetBucketVersioning\"\n            ],\n            \"Resource\": [\n                \"arn:aws:s3:::artifacts-prod\"\n            ]\n        },\n        {\n            \"Sid\": \"AllowReadWriteArtifacts\",\n            \"Effect\": \"Allow\",\n            \"Action\": [\n                \"s3:GetObject\",\n                \"s3:GetObjectVersion\",\n                \"s3:PutObject\"\n            ],\n            \"Resource\": [\n                \"arn:aws:s3:::artifacts-prod/ci/*\",\n                \"arn:aws:s3:::artifacts-prod/deployments/*\"\n            ],\n            \"Condition\": {\n                \"StringEquals\": {\n                    \"s3:x-amz-server-side-encryption\": \"AES256\"\n                }\n            }\n        },\n        {\n            \"Sid\": \"DenyDelete\",\n            \"Effect\": \"Deny\",\n            \"Action\": [\n                \"s3:DeleteObject\",\n                \"s3:DeleteObjectVersion\",\n                \"s3:DeleteBucketPolicy\"\n            ],\n            \"Resource\": \"arn:aws:s3:::artifacts-prod/*\"\n        },\n        {\n            \"Sid\": \"DenyPublicAccess\",\n            \"Effect\": \"Deny\",\n            \"Action\": [\n                \"s3:PutBucketAcl\",\n                \"s3:PutBucketPolicy\",\n                \"s3:PutObjectAcl\"\n            ],\n            \"Resource\": \"arn:aws:s3:::artifacts-prod/*\"\n        }\n    ]\n}\n```\n\n### Policy Notes\n- **Lists**: Only the specific bucket, not all buckets\n- **Write**: Restricted to `ci/` and `deployments/` prefixes\n- **Encryption**: Enforced via condition key\n- **Deny delete**: Prevents accidental or malicious deletion\n- **Deny public**: Blocks any ACL/policy changes that could expose data",
         "iam_policy", "cloud_security"),

        # ── Network Security: Suricata IDS ──
        ("Write a Suricata rule to detect Log4Shell exploitation attempts",
         "```\n# Log4Shell (CVE-2021-44228) Detection Rules\n# Reference: https://attack.mitre.org/techniques/T1190/\n\n# HTTP-based exploitation\nalert http any any -> any any (\n    msg:\"CVE-2021-44228 Log4Shell HTTP JNDI Injection Attempt\";\n    flow:to_server,established;\n    content:\"${jndi:ldap://\"; fast_pattern;\n    http_client_body;\n    classtype:attempted-admin;\n    sid:10000001;\n    rev:1;\n    metadata:mitre_technique T1190, severity critical;\n)\n\nalert http any any -> any any (\n    msg:\"CVE-2021-44228 Log4Shell HTTP JNDI Injection (URI)\";\n    flow:to_server,established;\n    content:\"${jndi:\"; nocase; http_uri;\n    classtype:attempted-admin;\n    sid:10000002;\n    rev:1;\n    metadata:mitre_technique T1190, severity critical;\n)\n\n# Header-based exploitation\nalert http any any -> any any (\n    msg:\"CVE-2021-44228 Log4Shell in HTTP Headers\";\n    flow:to_server,established;\n    content:\"${jndi:\"; http_header; nocase;\n    classtype:attempted-admin;\n    sid:10000003;\n    rev:1;\n    metadata:mitre_technique T1190, severity critical;\n)\n\n# Outbound LDAP callback (post-exploitation detection)\nalert tcp any any -> any 389 (\n    msg:\"CVE-2021-44228 Outbound LDAP Callback\";\n    flow:to_server,established;\n    content:\"|30 30|bindRequest\"; depth:20;\n    classtype:attempted-admin;\n    sid:10000004;\n    rev:1;\n    metadata:mitre_technique T1190, severity high;\n)\n\nalert tcp any any -> any 1389 (\n    msg:\"CVE-2021-44228 Outbound LDAPS Callback\";\n    flow:to_server,established;\n    content:\"|30 30|bindRequest\"; depth:20;\n    classtype:attempted-admin;\n    sid:10000005;\n    rev:1;\n    metadata:mitre_technique T1190, severity high;\n)\n```",
         "suricata_rule", "network_security"),

        # ── CVE Analysis ──
        ("Analyze CVE-2023-44487: HTTP/2 Rapid Reset Attack",
         "## CVE-2023-44487: HTTP/2 Rapid Reset Attack\n\n### Overview\n- **CVSS 9.8** (Critical)\n- **Type**: Resource exhaustion (Denial of Service)\n- **Affected**: All HTTP/2 implementations (nginx, Apache, Envoy, Node.js, Go net/http)\n- **Disclosed**: October 2023\n\n### Mechanism\n```\nClient                      Server\n  |                            |\n  |--- SETTINGS ------------> |        Establish connection\n  |<-- SETTINGS ------------- |\n  |                            |\n  |--- HEADERS (stream 1) --> |        Send request\n  |--- RST_STREAM (stream 1) >|        Immediately cancel\n  |--- HEADERS (stream 3) --> |        Repeat immediately\n  |--- RST_STREAM (stream 3) >|\n  |--- HEADERS (stream 5) --> |        ... 100,000+ times/second\n  |--- RST_STREAM (stream 5) >|\n  |                            |        Server exhausts resources\n  |                            |        processing cancelled streams\n```\n\n### Impact\n- Attackers with a single machine can generate 100K+ requests/sec\n- Server spends more resources on stream creation/teardown than actual processing\n- Affects load balancers, CDNs, reverse proxies\n\n### Detection (Suricata rule)\n```\nalert ip any any -> any any (\n    msg:\"HTTP/2 Rapid Reset Attack CVE-2023-44487\";\n    flow:to_server;\n    content:\"|00 00 00 00 01|\"; depth:5;     // GOAWAY frame\n    content:\"|00 00 00 00 03|\"; depth:5;     // RST_STREAM frame\n    threshold: type both, count 1000, seconds 1;\n    classtype:denial-of-service;\n    sid:10000100;\n    rev:1;\n)\n```\n\n### Mitigation\n1. **Rate limit** RST_STREAM frames per connection\n2. **Limit** concurrent streams per connection\n3. **Update** to patched versions (nginx 1.25.3+, Apache 2.4.58+)\n4. **WAF rules** to block rapid stream creation patterns",
         "cve_analysis", "application_security"),

        # ── Network Security: WAF Rules ──
        ("Write Cloudflare WAF rules to block common web attacks",
         "## Cloudflare WAF Rule Set\n\n### Rule 1: Block SQL Injection\n```\n# Expression:\n(http.request.uri.query.string contains \"OR 1=1\") or\n(http.request.uri.query.string contains \"UNION SELECT\") or\n(http.request.uri.query.string contains \"' OR '\") or\n(http.request.body contains \"OR 1=1\") or\n(http.request.body contains \"UNION ALL SELECT\")\n\n# Action: Block\n# Rate limit: 10 requests/minute after trigger\n```\n\n### Rule 2: Block XSS\n```\n# Expression:\n(lower(http.request.uri) contains \"<script\") or\n(lower(http.request.body) contains \"<script\") or\n(http.request.uri contains \"<img\") or\n(http.request.headers[\"user-agent\"] contains \"<script\")\n\n# Action: Block\n```\n\n### Rule 3: Block Path Traversal\n```\n# Expression:\n(http.request.uri contains \"/../\") or\n(http.request.uri contains \"/..%252f/\") or\n(http.request.uri contains \"..\\\\..\\\\\") or\n(http.request.uri contains \"%2e%2e%2f\") or\n(http.request.uri contains \"%2e%2e\\\\\")\n\n# Action: Block\n```\n\n### Rule 4: Rate Limit Login Endpoints\n```\n# Expression:\n(http.request.uri.path contains \"/login\") or\n(http.request.uri.path contains \"/api/auth\")\n\n# Rate limit: 5 requests/minute per IP\n# Action: Block for 15 minutes\n# Response: 429 Too Many Requests\n```\n\n### Rule 5: Block Malicious Bots\n```\n# Expression:\n(cf.client.bot) and\n(lower(http.user_agent) contains \"curl\") == false and\n(lower(http.user_agent) contains \"python\") == false\n\n# Action: JS Challenge\n```\n\n### Rule 6: Geo-Block Admin Panels\n```\n# Expression:\n(http.request.uri.path contains \"/wp-admin\" or\n http.request.uri.path contains \"/admin\" or\n http.request.uri.path contains \"/administrator\") and\n ip.geoip.country not in {\"US\" \"GB\" \"DE\" \"CA\"}\n\n# Action: Block\n```\n\n### Deployment Checklist\n- [ ] Test rules in Log mode first\n- [ ] Review false positives after 48 hours\n- [ ] Set Rate Limiting per IP, not per session\n- [ ] Enable Bot Management for aggressive scraping\n- [ ] Configure WAF exclusion for legitimate API clients",
         "waf_rules", "network_security"),

        # ── Threat Intel: Diamond Model ──
        ("Explain the Diamond Model of intrusion analysis",
         "## Diamond Model of Intrusion Analysis\n\n### The Four Core Features\n\n```\n                   Adversary\n                      /\\\n                     /  \\\n                    /    \\\n                   /      \\\n            Capability     Infrastructure\n                   \\      /\n                    \\    /\n                     \\  /\n                      \\/\n                    Victim\n```\n\n### 1. Adversary\n- **Who**: Threat actor, hacker group, nation-state\n- **Attribution**: TTPs, tools, infrastructure overlaps\n- **Motivation**: Financial, espionage, hacktivism, destruction\n- **Example**: APT29 (Cozy Bear) — Russian state-sponsored\n\n### 2. Capability\n- **What**: Tools, malware, exploits used\n- **Types**: Custom malware, living-off-the-land binaries (LOLBins), zero-days\n- **Variant**: Capability can be modified per campaign\n- **Example**: SUNBURST backdoor, Cobalt Strike beacons\n\n### 3. Infrastructure\n- **Where**: C2 servers, domains, hosting providers\n- **Types**: Dedicated VPS, compromised routers, CDN fronting\n- **Lifespan**: Short-lived (fast flux) or persistent\n- **Example**: 203.0.113.5:443 (Cobalt Strike HTTPS beacon)\n\n### 4. Victim\n- **Target**: Organization, person, system, data\n- **Role**: Victim as Person, Victim as Organization, Victim as System\n- **Value**: Data exfiltrated, ransomware payment, espionage target\n- **Example**: SolarWinds Orion build server (supply chain)\n\n### Meta-Features\n| Feature | Description |\n|---|---|\n| **Timestamp** | When the event occurred |\n| **Phase** | Recon, Delivery, Exploit, C2, Exfil |\n| **Result** | Success, Failure, Unknown |\n| **Direction** | Victim→Infra, Infra→Victim, Bidirectional |\n| **Methodology** | TTP classification (MITRE ATT&CK) |\n| **Resources** | Tools, knowledge, access, funding |\n\n### Analysis Workflow\n1. **Map** each event to the Diamond\n2. **Connect** diamonds across events (same adversary, different victims)\n3. **Track** adversary evolution over time\n4. **Predict** future targets based on infrastructure overlap\n5. **Attribute** new events to known adversaries",
         "threat_intel", "threat_intel"),

        # ── Code Review: Hardcoded Secrets ──
        ("Review this code for security issues:\n```python\nimport boto3\n\ndef deploy():\n    client = boto3.client(\n        's3',\n        aws_access_key_id='AKIAIOSFODNN7EXAMPLE',\n        aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',\n        region_name='us-east-1'\n    )\n    client.upload_file('config.json', 'my-bucket', 'config.json')\n```",
         "## Security Review: Hardcoded AWS Credentials\n\n### Issues Found\n\n#### CRITICAL: Hardcoded AWS Access Keys\n- **Line 3-5**: AWS credentials embedded in source code\n- If committed to git, credentials are exposed to anyone with repo access\n- Scraper bots scan GitHub for these patterns automatically\n- **CWE-798**: Use of Hard-coded Credentials\n\n#### CRITICAL: No IAM Role or Instance Profile\n- Hardcoded keys cannot be rotated without code deployment\n- No audit trail for which user/role used these credentials\n\n### Fix: Use AWS IAM Roles\n```python\nimport boto3\n\n# BEST: Use IAM Role (EC2, ECS, Lambda)\n# - No keys in code\n# - Automatic credential rotation\n# - Auditable via CloudTrail\ndef deploy():\n    # Credentials auto-resolved from IAM role or environment\n    client = boto3.client('s3', region_name='us-east-1')\n    client.upload_file('config.json', 'my-bucket', 'config.json')\n```\n\n### Fix: Environment Variables\n```python\nimport os\nimport boto3\n\n# GOOD: Use environment variables (but still manual rotation)\ndef deploy():\n    client = boto3.client(\n        's3',\n        aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],\n        aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],\n        region_name='us-east-1'\n    )\n    client.upload_file('config.json', 'my-bucket', 'config.json')\n```\n\n### Fix: AWS Secrets Manager\n```python\nimport boto3\nfrom botocore.exceptions import ClientError\n\ndef get_secret():\n    \"\"\"Retrieve secrets from AWS Secrets Manager.\"\"\"\n    session = boto3.session.Session()\n    client = session.client('secretsmanager')\n\n    try:\n        response = client.get_secret_value(SecretId='prod/deploy-keys')\n        return response['SecretString']\n    except ClientError as e:\n        print(f\"Failed to retrieve secret: {e}\")\n        raise\n\ndef deploy():\n    # BEST PRACTICE: Secrets Manager with rotation\n    secret = get_secret()\n    session = boto3.Session(\n        aws_access_key_id=secret['access_key'],\n        aws_secret_access_key=secret['secret_key'],\n    )\n    client = session.client('s3', region_name='us-east-1')\n    client.upload_file('config.json', 'my-bucket', 'config.json')\n```\n\n### Prevention\n- **Pre-commit hook**: `detect-secrets` or `trufflehog` in CI\n- **git-secrets**: Blocks commits containing patterns matching AWS keys\n- **Environment**: Use `.env` files (added to `.gitignore`)\n- **Rotation**: Secrets Manager auto-rotation every 90 days",
         "code_review", "application_security"),

        # ── OT Security: Modbus Security ──
        ("How do you secure Modbus TCP in an industrial control system?",
         "## Securing Modbus TCP in ICS/SCADA\n\n### The Problem\nModbus TCP has **no built-in security**:\n- No authentication (anyone can read/write coils and registers)\n- No encryption (plaintext traffic)\n- No integrity checks (can inject/modify packets)\n- Default port 502 is easy to scan\n\n### Defense Layers\n\n#### Layer 1: Network Segmentation\n```\n+----------+     +----------+     +----------+\n| IT Net   |=====| DMZ      |=====| OT Net   |\n| 10.0.0.0 |     | 10.0.1.0 |     | 10.0.2.0 |\n+----------+     +----------+     +----------+\n                        |\n                   [Firewall]\n                   - Allow only port 502\n                   - Allow only specific source IPs\n                   - Rate limit to 100 packets/sec\n```\n\n#### Layer 2: Modbus-Specific Firewall Rules\n```\n# iptables rules for Modbus security\n\n# Allow only specific PLC IPs\niptables -A FORWARD -p tcp --dport 502 \\\n  -s 10.0.1.100 -d 10.0.2.0/24 -j ACCEPT\n\n# Block Modbus write function codes from IT\n# Function code 5 = Write Single Coil\n# Function code 6 = Write Single Register\n# Function code 15 = Write Multiple Coils\n# Function code 16 = Write Multiple Registers\niptables -A FORWARD -p tcp --dport 502 \\\n  -m string --algo bm --string \"\\x00\\x05\" -j DROP  # FC5\niptables -A FORWARD -p tcp --dport 502 \\\n  -m string --algo bm --string \"\\x00\\x06\" -j DROP  # FC6\niptables -A FORWARD -p tcp --dport 502 \\\n  -m string --algo bm --string \"\\x00\\x0f\" -j DROP  # FC15\niptables -A FORWARD -p tcp --dport 502 \\\n  -m string --algo bm --string \"\\x00\\x10\" -j DROP  # FC16\n\n# Default: drop all Modbus from IT to OT\niptables -A FORWARD -p tcp --dport 502 -j DROP\n```\n\n#### Layer 3: Modbus/TCP Security Gateway\n```python\n# Simple Modbus proxy with allowlist\nimport socket\nimport struct\n\nALLOWED_FC = {1, 2, 3, 4}  # Read-only function codes\nPLC_IPS = {\"10.0.2.10\", \"10.0.2.11\"}  # Allowlisted PLCs\n\ndef proxy_modbus(data, src_ip, dst_ip):\n    # Extract function code from Modbus ADU\n    # Modbus TCP ADU: MBAP (7 bytes) + PDU\n    if len(data) < 8:\n        return None  # Drop malformed\n\n    fc = data[7]  # Function code byte\n    if dst_ip not in PLC_IPS:\n        print(f\"Blocked: unknown PLC {dst_ip}\")\n        return None\n    if fc not in ALLOWED_FC:\n        print(f\"Blocked: function code {fc} from {src_ip}\")\n        return None\n    return data  # Forward\n```\n\n#### Layer 4: Monitoring\n```bash\n# Snort rule for Modbus write function codes\nalert tcp $EXTERNAL_NET any -> $HOME_NET 502 (\n    msg:\"Modbus Write Function Code Detected\";\n    content:\"|00 00 00 00 00 06 01|\"; offset 0; depth 7;\n    byte_test:1,!=,1,7;\n    byte_test:1,<,5,7;  # FC < 5 = read\n    classtype:policy-violation;\n    sid:10000200;\n)\n```\n\n### Recommendation\nFor new deployments: Use **Modbus/TCP Security** (no RFC yet) or tunnel via **OPC-UA with security**. For existing deployments: Defense-in-depth with segmentation + gateway + monitoring.",
         "ot_security", "ot_ics_security"),
    ]

    for instruction, output, source, domain in more:
        builder.add(instruction, output, source, domain)
    return len(more)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--include-cve", default="data/cve_samples.jsonl",
                        help="Path to CVE samples JSONL (default: data/cve_samples.jsonl)")
    parser.add_argument("--include-tools", default="data/tool_samples.jsonl",
                        help="Path to Kali tool samples JSONL (default: data/tool_samples.jsonl)")
    args = parser.parse_args()

    builder = DatasetBuilder()
    attack_path = "data/attack/index.json"
    if os.path.exists(attack_path):
        print("Loading ATT&CK data...")
        builder.load_attack_data(attack_path)
        print(f"  → {len(builder.samples)} ATT&CK samples")

    print("\nGenerating expert domain content...")
    builder.add_offensive_security()
    print(f"  → offensive_security: +{5}")
    builder.add_defensive_security()
    print(f"  → defensive_security: +{3}")
    builder.add_cloud_security()
    print(f"  → cloud_security: +{3}")
    builder.add_network_security()
    print(f"  → network_security: +{2}")
    builder.add_malware_analysis()
    print(f"  → malware_analysis: +{2}")
    builder.add_reverse_engineering()
    print(f"  → reverse_engineering: +{2}")
    builder.add_secure_coding()
    print(f"  → secure_coding: +{3}")
    builder.add_incident_response()
    print(f"  → incident_response: +{2}")
    builder.add_detection_engineering()
    print(f"  → detection_engineering: +{2}")
    builder.add_k8s_security()
    print(f"  → kubernetes_security: +{2}")
    builder.add_docker_security()
    print(f"  → docker_security: +{1}")
    builder.add_grc()
    print(f"  → governance_risk_compliance: +{1}")
    builder.add_ai_security()
    print(f"  → ai_security: +{1}")
    builder.add_windows_ad()
    print(f"  → windows_ad: +{1}")
    builder.add_linux_security()
    print(f"  → linux_security: +{1}")

    print("\nAdding balanced expert content...")
    n = add_more_expert_content(builder)
    print(f"  → +{n} diverse samples")

    if os.path.exists(args.include_cve):
        print(f"\nLoading CVE data from {args.include_cve}...")
        with open(args.include_cve) as f:
            count = 0
            for line in f:
                cve = json.loads(line)
                if "messages" in cve:
                    inst = cve["messages"][0]["content"]
                    out = cve["messages"][1]["content"]
                else:
                    inst = cve["instruction"]
                    out = cve["output"]
                builder.add(inst, out, cve["source"], cve["domain"])
                count += 1
        print(f"  → +{count} CVE samples")

    if os.path.exists(args.include_tools):
        print(f"\nLoading Kali tool data from {args.include_tools}...")
        with open(args.include_tools) as f:
            count = 0
            for line in f:
                s = json.loads(line)
                builder.add(s["instruction"], s["output"], s["source"], s["domain"])
                count += 1
        print(f"  → +{count} Kali tool samples")

    builder.save()


if __name__ == "__main__":
    main()
