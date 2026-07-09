#!/usr/bin/env python3
"""Cybersecurity dataset scraper -> Axolotl 'alpaca' JSONL.

Collects training samples from public, license-friendly sources and
normalizes them into instruction/input/output records.

Sources (all public / freely usable):
  - NVD CVE API (nvd.nist.gov)  -> vulnerability explanation + remediation
  - MITRE CWE list              -> weakness descriptions
  - rings-of-power/vuln-java    -> vulnerable vs fixed code pairs (MIT)
  - secureauth01/cybersecurity-dataset (HuggingFace) -> Q&A pairs

Network access required. Only collects metadata + descriptions, never
exploit payloads for live systems. Output is for authorized research.

Usage:
  python3 scripts/scrape_dataset.py --out data/raw/cyber_scraped.jsonl \
      --cve-limit 200 --cwe-limit 100
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error

try:
    import requests
except ImportError:
    requests = None

UA = "cyber-llm-scraper/0.1 (authorized research)"


def _get(url, params=None, timeout=30):
    if requests:
        r = requests.get(url, params=params, headers={"User-Agent": UA}, timeout=timeout)
        r.raise_for_status()
        return r
    # fallback to urllib
    if params:
        from urllib.parse import urlencode
        url = url + "?" + urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        class _R:
            pass
        out = _R()
        out.text = resp.read().decode("utf-8", "replace")
        out.status_code = resp.status
        return out


# ---------- CVE (NVD) ----------
def scrape_cve(limit=200, delay=6.0, api_key=None):
    recs = []
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    fetched = 0
    start = 0
    while fetched < limit:
        try:
            headers = {"User-Agent": UA}
            if api_key:
                headers["apiKey"] = api_key
            if requests:
                r = requests.get(url, params={"resultsPerPage": 50, "startIndex": start},
                                 headers=headers, timeout=30)
                r.raise_for_status()
                data = json.loads(r.text)
            else:
                r = _get(url, params={"resultsPerPage": 50, "startIndex": start})
                data = json.loads(r.text)
        except Exception as e:  # noqa
            print(f"[cve] fetch error: {e}", file=sys.stderr)
            break
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        for v in vulns:
            cve = v.get("cve", {})
            cid = cve.get("id", "")
            descr = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    descr = d.get("description", "")
                    break
            metrics = cve.get("metrics", {})
            sev = ""
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if k in metrics:
                    sev = metrics[k][0].get("cvssData", {}).get("baseSeverity", "")
                    break
            if not descr:
                continue
            out = f"CVE ID: {cid}\nSeverity: {sev or 'N/A'}\n\n{descr}\n\n" \
                  f"Remediation guidance: patch to a fixed version, apply vendor " \
                  f"advisory mitigations, and validate input handling per OWASP."
            recs.append({
                "instruction": f"Summarize the vulnerability {cid} and how to remediate it.",
                "input": descr,
                "output": out,
            })
            fetched += 1
            if fetched >= limit:
                break
        start += 50
        time.sleep(delay)
    return recs


# ---------- CWE (MITRE) ----------
def scrape_cwe(limit=100):
    recs = []
    url = "https://cwe.mitre.org/data/published/cwe_latest.xml.zip"
    # MITRE CWE is large; use the lightweight JSON views if available.
    # Fallback: scrape the CWE weakness list page.
    try:
        r = _get("https://cwe.mitre.org/data/definitions/699.html", timeout=30)
        import re
        # crude extraction of CWE id + name from the 699 (software) list
        items = re.findall(r">CWE-(\d+)</a>\s*([^<]+)<", r.text)
        for cid, name in items[:limit]:
            recs.append({
                "instruction": f"Explain the software weakness CWE-{cid} ({name.strip()}) and how to prevent it.",
                "input": "",
                "output": f"CWE-{cid}: {name.strip()}. This is a class of software weakness. "
                          f"Prevention: follow secure coding practices, input validation, "
                          f"and threat modeling mapped to this weakness category.",
            })
    except Exception as e:  # noqa
        print(f"[cwe] fetch error: {e}", file=sys.stderr)
    return recs


# ---------- HuggingFace cybersecurity Q&A dataset ----------
def scrape_hf_dataset(name="secureauth01/cybersecurity-dataset", limit=200):
    recs = []
    # Stream the first parquet shard via the HF datasets server.
    url = f"https://datasets-server.huggingface.co/rows?dataset={name}&config=default&split=train&offset=0&length={limit}"
    try:
        r = _get(url, timeout=60)
        data = json.loads(r.text)
        for row in data.get("rows", []):
            feat = row.get("row", {})
            q = feat.get("prompt") or feat.get("question") or feat.get("instruction")
            a = feat.get("response") or feat.get("answer") or feat.get("output")
            if q and a:
                recs.append({"instruction": str(q), "input": "", "output": str(a)})
    except Exception as e:  # noqa
        print(f"[hf] {name} fetch error: {e}", file=sys.stderr)
    return recs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/raw/cyber_scraped.jsonl")
    ap.add_argument("--cve-limit", type=int, default=200)
    ap.add_argument("--cwe-limit", type=int, default=100)
    ap.add_argument("--hf-limit", type=int, default=200)
    ap.add_argument("--hf-name", default="secureauth01/cybersecurity-dataset")
    ap.add_argument("--nvd-key", default=os.environ.get("NVD_API_KEY", ""),
                    help="NVD API key to avoid 429 rate limits")
    args = ap.parse_args()

    if requests is None:
        print("Note: 'requests' not installed; using urllib fallback.", file=sys.stderr)

    recs = []
    print("Scraping CVE...")
    recs += scrape_cve(limit=args.cve_limit, api_key=args.nvd_key)
    print("Scraping CWE...")
    recs += scrape_cwe(limit=args.cwe_limit)
    print("Scraping HF Q&A...")
    recs += scrape_hf_dataset(name=args.hf_name, limit=args.hf_limit)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    seen = set()
    n = 0
    with open(args.out, "w") as f:
        for r in recs:
            key = (r["instruction"], r["input"], r["output"])
            if key in seen:
                continue
            seen.add(key)
            f.write(json.dumps(r) + "\n")
            n += 1
    print(f"Wrote {n} scraped samples to {args.out}")


if __name__ == "__main__":
    main()
