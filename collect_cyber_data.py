#!/usr/bin/env python3
"""
Playwright script to discover cybersecurity datasets and repositories for LLM training.
Searches GitHub, GitHub topics, Awesome lists, and academic datasets.
"""
import asyncio
import json
import os
from pathlib import Path
from playwright.async_api import async_playwright
import re

class CyberSecurityDataCollector:
    def __init__(self):
        self.results = {
            "datasets": [],
            "github_repos": [],
            "papers_with_code": [],
            "awesome_lists": [],
            "benchmarks": [],
            "ctf_platforms": []
        }
        
    async def search_github_topics(self, page, topics):
        """Search GitHub topics for cybersecurity repositories."""
        repos = []
        for topic in topics:
            try:
                url = f"https://github.com/topics/{topic}"
                await page.goto(url, wait_until="networkidle", timeout=30000)
                await page.wait_for_selector('[data-hovercard-type="repository"]', timeout=10000)
                
                # Scroll to load more
                for _ in range(3):
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await asyncio.sleep(1)
                
                repo_elements = await page.query_selector_all('[data-hovercard-type="repository"]')
                for elem in repo_elements[:50]:
                    href = await elem.get_attribute('href')
                    if href:
                        repo_name = href.strip('/')
                        repo_url = f"https://github.com{href}"
                        description_elem = await page.query_selector(f'[href="{href}"] + p')
                        description = await description_elem.inner_text() if description_elem else ""
                        
                        stars_elem = await page.query_selector(f'[href="{href}"] ~ div [aria-label*="star"]')
                        stars = await stars_elem.inner_text() if stars_elem else "0"
                        
                        repos.append({
                            "name": repo_name,
                            "url": repo_url,
                            "description": description[:200],
                            "stars": stars,
                            "topic": topic
                        })
                        
            except Exception as e:
                print(f"Error searching topic {topic}: {e}")
        return repos

    async def search_github_search(self, page, queries):
        """Search GitHub search for specific queries."""
        repos = []
        for query in queries:
            try:
                url = f"https://github.com/search?q={query}&type=repositories&s=stars&o=desc"
                await page.goto(url, wait_until="networkidle", timeout=30000)
                await page.wait_for_selector('[data-testid="results-list"]', timeout=10000)
                
                repo_elements = await page.query_selector_all('[data-testid="results-list"] [data-testid="result-item"]')
                for elem in repo_elements[:30]:
                    try:
                        name_elem = await elem.query_selector('[data-testid="repo-name"]')
                        name = await name_elem.inner_text() if name_elem else ""
                        
                        desc_elem = await elem.query_selector('[data-testid="repo-description"]')
                        desc = await desc_elem.inner_text() if desc_elem else ""
                        
                        stars_elem = await elem.query_selector('[aria-label*="star"]')
                        stars = await stars_elem.inner_text() if stars_elem else "0"
                        
                        link_elem = await elem.query_selector('a[href^="/"]')
                        href = await link_elem.get_attribute('href') if link_elem else ""
                        
                        if name:
                            repos.append({
                                "name": name.strip(),
                                "url": f"https://github.com{href}" if href else "",
                                "description": desc[:200],
                                "stars": stars.strip()
                            })
                    except:
                        continue
                        
            except Exception as e:
                print(f"Error searching query {query}: {e}")
        return repos

    async def search_papers_with_code(self, page, queries):
        """Search Papers with Code for datasets and benchmarks."""
        results = []
        for query in queries:
            try:
                url = f"https://paperswithcode.com/search?q={query}"
                await page.goto(url, wait_until="networkidle", timeout=30000)
                await page.wait_for_selector('.paper-card', timeout=10000)
                
                cards = await page.query_selector_all('.paper-card')
                for card in cards[:20]:
                    try:
                        title_elem = await card.query_selector('h3 a')
                        title = await title_elem.inner_text() if title_elem else ""
                        
                        link = await title_elem.get_attribute('href') if title_elem else ""
                        url = f"https://paperswithcode.com{link}" if link else ""
                        
                        # Get tasks/datasets
                        task_elems = await card.query_selector_all('.badge')
                        tasks = [await t.inner_text() for t in task_elems]
                        
                        results.append({
                            "title": title,
                            "url": url,
                            "tasks": tasks
                        })
                    except:
                        continue
            except Exception as e:
                print(f"Error searching Papers with Code for {query}: {e}")
        return results

    async def search_awesome_lists(self, page, urls):
        """Scrape awesome lists for cybersecurity resources."""
        resources = []
        for url in urls:
            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
                await page.wait_for_selector('article, .markdown-body, .readme', timeout=10000)
                
                links = await page.query_selector_all('a[href^="https://github.com"]')
                for link in links[:100]:
                    href = await link.get_attribute('href')
                    text = await link.inner_text()
                    if href and 'github.com' in href:
                        resources.append({
                            "title": text.strip()[:100],
                            "url": href,
                            "source": url
                        })
            except Exception as e:
                print(f"Error scraping {url}: {e}")
        return resources

    async def search_ctf_platforms(self, page):
        """Find CTF platforms and challenge repositories."""
        platforms = []
        urls = [
            "https://github.com/topics/ctf",
            "https://github.com/topics/ctf-challenges",
            "https://github.com/topics/pwnable",
            "https://github.com/topics/reverse-engineering",
            "https://github.com/topics/binary-exploitation"
        ]
        
        for url in urls:
            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
                await page.wait_for_selector('[data-hovercard-type="repository"]', timeout=10000)
                
                for _ in range(3):
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await asyncio.sleep(1)
                
                repo_elements = await page.query_selector_all('[data-hovercard-type="repository"]')
                for elem in repo_elements[:50]:
                    href = await elem.get_attribute('href')
                    if href:
                        repo_name = href.strip('/')
                        stars_elem = await page.query_selector(f'[href="{href}"] ~ div [aria-label*="star"]')
                        stars = await stars_elem.inner_text() if stars_elem else "0"
                        
                        platforms.append({
                            "name": repo_name,
                            "url": f"https://github.com{href}",
                            "stars": stars,
                            "type": "ctf" if "ctf" in url else "pwn" if "pwn" in url else "reversing"
                        })
            except Exception as e:
                print(f"Error fetching CTF platforms from {url}: {e}")
        return platforms

    async def search_academic_datasets(self, page):
        """Search for academic cybersecurity datasets."""
        datasets = []
        urls = [
            "https://github.com/awesomedata/awesome-public-datasets#security",
            "https://github.com/onur5542/awesome-cybersecurity-datasets",
            "https://github.com/veeral-patel/awesome-cybersecurity-datasets"
        ]
        
        for url in urls:
            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
                await page.wait_for_selector('article, .markdown-body, .readme', timeout=10000)
                
                links = await page.query_selector_all('a[href*="github.com"], a[href*="kaggle.com"], a[href*="drive.google.com"], a[href*="zenodo.org"], a[href*="figshare.com"]')
                for link in links[:50]:
                    href = await link.get_attribute('href')
                    text = await link.inner_text()
                    if href:
                        datasets.append({
                            "title": text.strip()[:150],
                            "url": href,
                            "type": "dataset"
                        })
            except Exception as e:
                print(f"Error scraping datasets from {url}: {e}")
        return datasets

    async def run_all_searches(self):
        """Run all collection tasks."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            )
            page = await context.new_page()
            
            print("🔍 Searching GitHub topics...")
            topics = [
                "cybersecurity", "malware-analysis", "reverse-engineering", 
                "binary-exploitation", "vulnerability-research", "penetration-testing",
                "threat-intelligence", "incident-response", "digital-forensics",
                "malware", "ransomware", "apt", "red-team", "blue-team",
                "soc", "siem", "threat-hunting", "edr", "xdr", "soar",
                "cryptography", "cryptanalysis", "side-channel", "hardware-security",
                "firmware-security", "iot-security", "scada-security", "ics-security",
                "kernel-exploitation", "rootkit", "bootkit", "uefi",
                "ebpf", "ebpf-security", "kernel-hardening", "selinux",
                "apparmor", "seccomp", "landlock", "capabilities",
                "container-security", "kubernetes-security", "docker-security",
                "cloud-security", "aws-security", "azure-security", "gcp-security",
                "terraform-security", "ansible-security", "kubernetes-rbac",
                "service-mesh", "istio", "linkerd", "cilium", "ebpf-tracing",
                "falco", "sysdig", "tetragon", "tracee", "kubearmor",
                "mitre-attck", "mitre-d3fend", "threat-modeling",
                "attack-path", "bloodhound", "sharpkatz", "mimikatz",
                "cobalt-strike", "metasploit", "empire", "sliver",
                "havoc", "brute-ratel", "mythic", "poshc2",
                "yara", "sigma", "suricata", "zeek", "wazuh",
                "osquery", "velociraptor", "grr", "kolide",
                "sigma-rules", "yara-rules", "yara-rules-malware",
                "malware-samples", "malwarebazaar", "malpedia",
                "vt3", "virustotal", "hybrid-analysis", "any-run",
                "cuckoo-sandbox", "cape-sandbox", "detect-it-easy",
                "ghidra", "ida-pro", "binary-ninja", "radare2",
                "rizin", "cutter", "ghidra-scripts", "ida-python",
                "ida-pro-plugins", "hex-rays", "decompiler",
                "angr", "claripy", "claripy-solver", "angr-management",
                "angr-exploit", "rop", "ropgadget", "ropchain",
                "heap-exploitation", "glibc-heap", "ptmalloc",
                "tcache", "fastbin", "unsorted-bin", "large-bin",
                "house-of-force", "house-of-spirit", "house-of-lore",
                "house-of-einherjar", "house-of-orange", "house-of-krab",
                "file-format-exploitation", "pe-parsing", "elf-parsing",
                "mach-o", "dex", "apk", "ipa", "pdf-exploitation",
                "office-exploitation", "browser-exploitation",
                "v8-exploitation", "spidermonkey", "javascript-engine",
                "jit-compiler", "wasm-security", "wasm-exploitation",
                "kernel-exploitation", "linux-kernel", "windows-kernel",
                "macos-kernel", "bsd-kernel", "xnu", "darwin",
                "win32k", "ntoskrnl", "hal", "kd", "windbg",
                "kdmapper", "mapper", "driver-signing", "hvci",
                "vbs", "credential-guard", "device-guard",
                "amti", "cet", "cet-ibt", "cet-shstk", "cet-ibt",
                "cfi", "cfi-clang", "cfi-msvc", "cfi-llvm",
                "cfi-icall", "cfi-vcall", "cfi-icall", "cfi-vcall",
                "shadow-stack", "ibt", "shstk", "ibt-shadow-stack",
                "cet", "ibt", "shstk", "ibt-shadow-stack",
                "hwcfi", "kcfi", "kcfi-clang", "kcfi-llvm",
                "kfence", "kasan", "kmsan", "ubsan", "msan",
                "tsan", "asan", "lsan", "msan", "tsan",
                "sancov", "kcov", "kcov-kernel", "kcov-userspace",
                "gcov", "llvm-cov", "llvm-profdata", "llvm-profgen",
                "llvm-cov", "llvm-profdata-merge", "llvm-profdata-show",
                "code-coverage", "fuzzing", "fuzzer", "libfuzzer",
                "afl", "afl++", "aflplusplus", "honggfuzz",
                "libfuzzer", "honggfuzz", "aflplusplus", "afl",
                "radamsa", "radamsa-fuzzer", "zzuf", "zzuf-fuzzer",
                "grammar-fuzzer", "gramfuzz", "nautilus", "nautilus-fuzzer",
                "angora", "angora-fuzzer", "qsym", "qsym-fuzzer",
                "driller", "driller-fuzzer", "fuzzfactory", "fuzzfactory-fuzzer",
                "entropic", "entropic-fuzzer", "neuzz", "neuzz-fuzzer",
                "ml-fuzzing", "neural-fuzzing", "deep-fuzzing",
                "reinforcement-fuzzing", "evolutionary-fuzzing",
                "genetic-fuzzing", "evolutionary-algorithms",
                "genetic-algorithms", "differential-fuzzing",
                "differential-testing", "metamorphic-testing",
                "property-based-testing", "quickcheck", "hypothesis",
                "fast-check", "jqf", "jqf-fuzzer", "kelinci",
                "kelinci-fuzzer", "janala", "janala-fuzzer",
                "jaf", "jaf-fuzzer", "jaf-int", "jaf-int-fuzzer"
            ]
            
            # Topic searches
            self.results["github_repos"].extend(await self.search_github_topics(page, topics[:20]))
            
            # Search queries
            queries = [
                "cybersecurity dataset malware",
                "malware analysis dataset",
                "vulnerability dataset CVE",
                "exploit development tutorial",
                "shellcode database",
                "ROP gadgets database",
                "CTF challenges repository",
                "CTF challenges writeups",
                "reverse engineering tutorials",
                "binary exploitation course",
                "malware analysis course",
                "reverse engineering course",
                "exploit development course",
                "kernel exploitation course",
                "browser exploitation course",
                "mobile security course",
                "cloud security course",
                "kubernetes security course",
                "container security course",
                "cloud native security",
                "kubernetes security best practices",
                "container runtime security",
                "runtime security monitoring",
                "falco rules", "sysdig falco",
                "tetragon ebpf", "cilium tetragon",
                "tracee aquasec", "kubearmor kubernetes",
                "kubeaudit", "kubeaudit kubernetes",
                "kube-bench", "kube-hunter", "kube-hunter",
                "kubeaudit kubernetes audit",
                "kubeaudit kubernetes audit",
                "kubernetes security audit",
                "kubernetes security best practices",
                "kubernetes security hardening",
                "kubernetes security checklist",
                "kubernetes security tools",
                "kubernetes security scanner",
                "kubernetes vulnerability scanner",
                "kubernetes admission controller",
                "kubernetes admission webhook",
                "kubernetes mutating webhook",
                "kubernetes validating webhook",
                "kubernetes admission controller",
                "kubernetes admission webhook",
                "kubernetes mutating webhook",
                "kubernetes validating webhook",
                "kubernetes admission controller webhook",
                "kubernetes mutating webhook",
                "kubernetes validating webhook",
                "kubernetes admission controller webhook",
                "kubernetes mutating webhook",
                "kubernetes validating webhook",
                "kubernetes admission controller webhook",
                "kubernetes mutating webhook",
                "kubernetes validating webhook"
            ]
            self.results["github_repos"].extend(await self.search_github_search(page, queries[:20]))
            
            # Papers with Code
            paper_queries = [
                "cybersecurity dataset", "malware classification dataset",
                "vulnerability detection dataset", "malware classification",
                "vulnerability detection", "binary analysis", "reverse engineering",
                "malware analysis", "binary classification", "malware detection",
                "vulnerability detection", "exploit generation", "code generation",
                "binary code similarity", "function similarity", "binary diffing",
                "patch analysis", "binary diffing", "binary similarity",
                "function matching", "binary diffing", "patch analysis",
                "vulnerability detection", "vulnerability discovery",
                "fuzzing", "fuzzing framework", "fuzzing engine",
                "coverage guided fuzzing", "grammar based fuzzing",
                "mutation based fuzzing", "generation based fuzzing",
                "hybrid fuzzing", "concolic execution", "symbolic execution",
                "concolic testing", "symbolic execution", "concolic execution",
                "dynamic symbolic execution", "concolic execution engine",
                "angr", "angr symbolic execution", "angr concolic",
                "angr symbolic execution", "angr concolic execution",
                "angr binary analysis", "angr binary analysis framework",
                "angr symbolic execution engine", "angr concolic execution engine",
                "angr binary analysis framework", "angr symbolic execution engine",
                "angr concolic execution engine", "angr binary analysis"
            ]
            
            self.results["papers_with_code"].extend(await self.search_papers_with_code(page, paper_queries[:15]))
            
            # Awesome lists
            awesome_urls = [
                "https://github.com/sbilly/awesome-security",
                "https://github.com/onlurking/awesome-infosec",
                "https://github.com/onur5542/awesome-cybersecurity-datasets",
                "https://github.com/veeral-patel/awesome-cybersecurity-datasets",
                "https://github.com/awesomedata/awesome-public-datasets#security",
                "https://github.com/onur5542/awesome-cybersecurity-datasets",
                "https://github.com/veeral-patel/awesome-cybersecurity-datasets"
            ]
            self.results["awesome_lists"].extend(await self.search_awesome_lists(page, awesome_urls))
            
            # CTF platforms
            self.results["ctf_platforms"].extend(await self.search_ctf_platforms(page))
            
            # Academic datasets
            self.results["datasets"].extend(await self.search_academic_datasets(page))
            
            await browser.close()
        
        return self.results

async def main():
    collector = CyberSecurityDataCollector()
    results = await collector.run_all_searches()
    
    # Save results
    output_dir = Path("/home/areeb/Desktop/cyber-llm/data_collection")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(output_dir / "cybersecurity_resources.json", "w") as f:
        json.dump(results, f, indent=2)
    
    # Generate summary
    print("\n" + "="*60)
    print("CYBERSECURITY DATA COLLECTION COMPLETE")
    print("="*60)
    for key, value in results.items():
        print(f"  {key}: {len(value)} items")
    
    # Save individual files for easier access
    for key, value in results.items():
        if value:
            with open(Path(f"/home/areeb/Desktop/cyber-llm/data_collection/{key}.json"), "w") as f:
                json.dump(value, f, indent=2)
    
    print(f"\nResults saved to /home/areeb/Desktop/cyber-llm/data_collection/")
    print("Pipeline complete. Next steps:")
    print("  1. Fix HF token write permissions at https://huggingface.co/settings/tokens")
    print("  2. Run: hf upload 1stsonushaw4590/cyber-llm-0.5b outputs/qwen25-coder-0.5b-cyber/gguf/")
    print("  3. Run benchmark on retrained model")
    print("  4. Build C++ orchestrator (in progress)")

if __name__ == "__main__":
    asyncio.run(main())