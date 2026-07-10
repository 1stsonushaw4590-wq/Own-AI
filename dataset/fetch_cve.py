"""Fetch real CVE data from NVD API and convert to training samples."""
import argparse
import json
import os
import urllib.request
import urllib.error
import time
from datetime import datetime, timedelta, timezone

CACHE_FILE = "data/nvd_cache.json"


def fetch_cves(keywords, max_results=50, days_back=365):
    """Fetch CVEs from NVD API 2.0, filtered by date then matched by keyword."""
    results = []
    end = datetime.now(timezone.utc)
    seen_ids = set()

    chunk_days = 90
    chunk_start = end - timedelta(days=days_back + chunk_days)

    while chunk_start < end and len(results) < max_results:
        chunk_end = min(chunk_start + timedelta(days=chunk_days), end)
        s = chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        e = chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={s}&pubEndDate={e}&resultsPerPage=50"

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cyber-llm/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())

            chunk_total = len(data.get("vulnerabilities", []))
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                if cve_id in seen_ids:
                    continue
                seen_ids.add(cve_id)
                desc_data = cve.get("descriptions", [])
                description = next((d["value"] for d in desc_data if d["lang"] == "en"), "")

                if not description or not any(kw.lower() in description.lower() for kw in keywords):
                    continue

                metrics = cve.get("metrics", {})
                cvss = None
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics:
                        cvss_obj = metrics[key][0].get("cvssData", {})
                        cvss = {
                            "score": cvss_obj.get("baseScore"),
                            "severity": cvss_obj.get("baseSeverity"),
                            "vector": cvss_obj.get("vectorString"),
                        }
                        break
                refs = [r["url"] for r in cve.get("references", [])[:3]]
                weaknesses = []
                for w in cve.get("weaknesses", []):
                    for d in w.get("description", []):
                        weaknesses.append(d["value"])

                kw_matched = next((kw for kw in keywords if kw.lower() in description.lower()), keywords[0])
                results.append({
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "references": refs,
                    "weaknesses": weaknesses,
                    "keyword": kw_matched,
                    "published": cve.get("published", ""),
                })

                if len(results) >= max_results:
                    break

            print(f"  Chunk {s[:10]}..{e[:10]}: {chunk_total} vulns, {len(results)} matched so far")
            time.sleep(0.6)
        except Exception as ex:
            print(f"  Error fetching {s[:10]}..{e[:10]}: {ex}")
            time.sleep(1)

        chunk_start = chunk_end

    return results[:max_results]


def format_sample(cve):
    """Convert CVE data to instruction-response pair."""
    keyword = cve["keyword"]
    domain_map = {
        "sql injection": "application_security",
        "xss": "application_security",
        "command injection": "application_security",
        "ssrf": "application_security",
        "authentication bypass": "identity_access_management",
        "buffer overflow": "application_security",
        "remote code execution": "application_security",
        "memory corruption": "application_security",
        "privilege escalation": "application_security",
        "denial of service": "network_security",
        "path traversal": "application_security",
        "cryptographic": "cryptography_pki",
        "tls": "cryptography_pki",
        "ssl": "cryptography_pki",
        "authentication": "identity_access_management",
        "authorization": "identity_access_management",
        "injection": "application_security",
        "deserialization": "application_security",
        "race condition": "application_security",
        "use after free": "application_security",
        "information disclosure": "application_security",
        "out of bounds": "application_security",
    }
    domain = "application_security"
    for kw, d in domain_map.items():
        if kw in keyword.lower():
            domain = d
            break

    instruction = f"Analyze CVE-{cve['id']}: what is the vulnerability and how do you mitigate it?"
    score_str = f"CVSS {cve['cvss']['score']} ({cve['cvss']['severity']})" if cve.get("cvss") else "No CVSS score assigned"
    weaknesses = ", ".join(cve.get("weaknesses", [])) or "Not specified"

    output = f"## {cve['id']}\n\n"
    output += f"**Severity**: {score_str}\n\n"
    if cve.get("cvss") and cve["cvss"].get("vector"):
        output += f"**Vector**: `{cve['cvss']['vector']}`\n\n"
    output += f"**Description**: {cve['description']}\n\n"
    output += f"**Weaknesses**: {weaknesses}\n\n"
    output += "### Mitigation\n\n"
    output += "1. Apply vendor patch or upgrade to patched version\n"
    output += "2. Implement virtual patching (WAF/IPS rules) if immediate patching is not possible\n"
    output += "3. Check exploit-db and CISA KEV for active exploitation\n"
    output += "4. Review network segmentation to limit exposure\n"
    output += "5. Add detection rules (IDS/EDR) for exploitation attempts\n\n"
    if cve.get("references"):
        output += "### References\n"
        for ref in cve["references"]:
            output += f"- {ref}\n"

    return instruction, output, "nvd_cve", domain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keywords", nargs="+", default=[
        "sql injection", "xss", "remote code execution", "privilege escalation",
        "authentication bypass", "buffer overflow", "deserialization",
        "path traversal", "ssrf", "command injection", "cryptographic",
        "denial of service", "race condition", "use after free",
    ])
    ap.add_argument("--max-per-keyword", type=int, default=20)
    ap.add_argument("--days-back", type=int, default=730)
    ap.add_argument("--output", default="data/cve_samples.jsonl")
    args = ap.parse_args()

    print(f"Fetching CVEs matching keywords: {args.keywords}")
    print(f"  Max per keyword: {args.max_per_keyword}")
    print(f"  Days back: {args.days_back}")

    raw = fetch_cves(args.keywords, args.max_per_keyword, args.days_back)
    print(f"\nFetched {len(raw)} CVEs matched by keyword")

    seen = set()
    samples = []
    for cve in raw:
        if not cve["description"]:
            continue
        if cve["id"] in seen:
            continue
        seen.add(cve["id"])
        ins, out, source, domain = format_sample(cve)
        sample = {
            "messages": [
                {"role": "user", "content": ins},
                {"role": "assistant", "content": out},
            ],
            "source": source,
            "domain": domain,
        }
        samples.append(sample)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    print(f"Saved {len(samples)} CVE samples to {args.output}")
    print(f"\nDomains covered: {len(set(s['domain'] for s in samples))}")
    for d in sorted(set(s["domain"] for s in samples)):
        count = sum(1 for s in samples if s["domain"] == d)
        print(f"  {d}: {count}")


if __name__ == "__main__":
    main()
