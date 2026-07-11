#!/usr/bin/env python3
"""
Fetch and process datasets from awesome-ml-for-cybersecurity
for cyber-LLM training data augmentation.
"""

import os
import json
import requests
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse

# High-value datasets for cyber-LLM training
CYBER_DATASETS = {
    # Network intrusion detection
    "ember": {
        "url": "https://github.com/endgameinc/ember",
        "description": "PE malware static analysis dataset (1M+ samples)",
        "type": "malware_analysis",
        "format": "json",
        "size_gb": 4.5,
        "priority": "high"
    },
    "drebin": {
        "url": "https://www.sec.cs.tu-bs.de/~danarp/drebin/",
        "description": "Android malware dataset (120K+ samples)",
        "type": "malware_analysis",
        "format": "pickle",
        "size_gb": 2.0,
        "priority": "high"
    },
    "ember_2018": {
        "url": "https://github.com/endgameinc/ember/tree/master/ember2018",
        "description": "Updated EMBER dataset",
        "type": "malware_analysis",
        "format": "json",
        "size_gb": 4.5,
        "priority": "high"
    },
    
    # Network traffic / intrusion
    "cic_ids2017": {
        "url": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "description": "CIC-IDS2017 network intrusion dataset (2.8M flows)",
        "type": "network_intrusion",
        "format": "csv",
        "size_gb": 8.0,
        "priority": "high"
    },
    "cic_ids2018": {
        "url": "https://www.unb.ca/cic/datasets/ids-2018.html",
        "description": "CIC-IDS2018 updated intrusion dataset",
        "type": "network_intrusion",
        "format": "csv",
        "size_gb": 12.0,
        "priority": "medium"
    },
    "unsw_nb15": {
        "url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "description": "UNSW-NB15 hybrid network intrusion dataset",
        "type": "network_intrusion",
        "format": "csv",
        "size_gb": 5.0,
        "priority": "high"
    },
    "nsl_kdd": {
        "url": "https://github.com/defcom17/NSL_KDD",
        "description": "NSL-KDD improved KDD Cup 99 dataset",
        "type": "network_intrusion",
        "format": "csv",
        "size_gb": 0.5,
        "priority": "medium"
    },
    "kddcup99": {
        "url": "http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html",
        "description": "Classic KDD Cup 99 intrusion detection",
        "type": "network_intrusion",
        "format": "csv",
        "size_gb": 2.0,
        "priority": "low"
    },
    
    # Malware / binary analysis
    "bodmas": {
        "url": "https://whyisyoung.github.io/BODMAS/",
        "description": "BODMAS PE malware dataset (47K samples)",
        "type": "malware_analysis",
        "format": "json",
        "size_gb": 10.0,
        "priority": "high"
    },
    "malware_training_sets": {
        "url": "https://github.com/marcoramilli/MalwareTrainingSets",
        "description": "Various malware training datasets",
        "type": "malware_analysis",
        "format": "mixed",
        "size_gb": 3.0,
        "priority": "medium"
    },
    "aktaion": {
        "url": "https://github.com/jzadeh/Aktaion/tree/master/data",
        "description": "Aktaion behavioral malware datasets",
        "type": "malware_analysis",
        "format": "json",
        "size_gb": 1.0,
        "priority": "medium"
    },
    
    # Web attacks / URLs
    "malicious_urls": {
        "url": "http://sysnet.ucsd.edu/projects/url/",
        "description": "Malicious URLs dataset (2M+ URLs)",
        "type": "web_attacks",
        "format": "txt",
        "size_gb": 1.0,
        "priority": "high"
    },
    "waf_queries": {
        "url": "https://github.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall",
        "description": "WAF malicious query dataset",
        "type": "web_attacks",
        "format": "csv",
        "size_gb": 0.5,
        "priority": "high"
    },
    "xss_payloads": {
        "url": "https://github.com/foospidy/payloads",
        "description": "XSS payloads collection",
        "type": "web_attacks",
        "format": "txt",
        "size_gb": 0.1,
        "priority": "medium"
    },
    "web_attack_payloads": {
        "url": "https://github.com/lcatro/WebShell-Detect-By-Machine-Learning",
        "description": "WebShell detection dataset",
        "type": "web_attacks",
        "format": "mixed",
        "size_gb": 0.2,
        "priority": "medium"
    },
    
    # Phishing / spam
    "phishing_corpus": {
        "url": "https://monkey.org/~jose/phishing/",
        "description": "PhishingCorpus dataset",
        "type": "phishing",
        "format": "eml",
        "size_gb": 0.5,
        "priority": "high"
    },
    "spam_corpus": {
        "url": "https://plg.uwaterloo.ca/~gvcormac/treccorpus07/",
        "description": "TREC 2007 Spam Corpus",
        "type": "phishing",
        "format": "eml",
        "size_gb": 2.0,
        "priority": "medium"
    },
    
    # PCAP / network forensics
    "netresec_pcaps": {
        "url": "http://www.netresec.com/?page=PcapFiles",
        "description": "Public PCAP files for forensics",
        "type": "network_forensics",
        "format": "pcap",
        "size_gb": 50.0,
        "priority": "low"
    },
    "stratosphere": {
        "url": "https://stratosphereips.org/category/dataset.html",
        "description": "Stratosphere IPS labeled network traffic",
        "type": "network_forensics",
        "format": "pcap",
        "size_gb": 10.0,
        "priority": "medium"
    },
    
    # Specialized
    "awid": {
        "url": "http://icsdweb.aegean.gr/awid/",
        "description": "Aegean Wireless Intrusion Dataset (AWID)",
        "type": "wireless",
        "format": "csv",
        "size_gb": 3.0,
        "priority": "medium"
    },
    "trec_spam": {
        "url": "https://plg.uwaterloo.ca/~gvcormac/treccorpus07/",
        "description": "TREC 2007 spam corpus",
        "type": "phishing",
        "format": "eml",
        "size_gb": 4.0,
        "priority": "medium"
    },
}


def download_dataset(name: str, info: Dict, output_dir: Path) -> bool:
    """Download a dataset if possible."""
    print(f"\n{'='*60}")
    print(f"Dataset: {name}")
    print(f"Description: {info['description']}")
    print(f"Type: {info['type']} | Size: {info['size_gb']} GB | Priority: {info['priority']}")
    print(f"Source: {info['url']}")
    
    # Create dataset directory
    ds_dir = output_dir / name
    ds_dir.mkdir(parents=True, exist_ok=True)
    
    # Save metadata
    meta = {
        "name": name,
        "source": info['url'],
        "description": info['description'],
        "type": info['type'],
        "size_gb": info['size_gb'],
        "priority": info['priority'],
        "status": "metadata_only"
    }
    
    # Try to download if it's a direct link
    try:
        # Some datasets have direct download links
        response = requests.get(info['url'], timeout=30, headers={'User-Agent': 'Mozilla/5.0'})
        
        if response.status_code == 200:
            # Check if it's a downloadable file
            content_type = response.headers.get('Content-Type', '')
            if 'html' not in content_type.lower() and len(response.content) > 1000:
                # Might be a direct download
                filename = os.path.basename(urlparse(info['url']).path)
                if not filename or '.' not in filename:
                    filename = f"{name}.dat"
                
                filepath = ds_dir / filename
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                
                meta['status'] = 'downloaded'
                meta['local_file'] = str(filepath)
                meta['size_bytes'] = len(response.content)
                print(f"  ✓ Downloaded: {filepath} ({len(response.content)} bytes)")
            else:
                print(f"  → HTML page, manual download needed")
        else:
            print(f"  → HTTP {response.status_code}, manual download needed")
            
    except Exception as e:
        print(f"  → Download failed: {e}")
        print(f"  → Manual download needed from: {info['url']}")
    
    # Save metadata
    with open(ds_dir / "metadata.json", 'w') as f:
        json.dump(meta, f, indent=2)
    
    return True


def create_training_samples(output_dir: Path) -> List[Dict]:
    """Create training samples from dataset descriptions."""
    samples = []
    
    for name, info in CYBER_DATASETS.items():
        # Create instruction-response pairs for each dataset
        samples.append({
            "instruction": f"What is the {name} dataset and how is it used in cybersecurity?",
            "output": f"""## {name.replace('_', ' ').title()}

**Description**: {info['description']}

**Type**: {info['type'].replace('_', ' ').title()}
**Size**: {info['size_gb']} GB
**Format**: {info['format'].upper()}
**Priority for Training**: {info['priority'].capitalize()}

**Source**: {info['url']}

**Use Cases**:
- {info['type'].replace('_', ' ').title()} model training
- Feature engineering for {info['type'].replace('_', ' ')}
- Benchmarking cybersecurity ML models
- Data augmentation for cyber-LLM

**Access**: Download from {info['url']} (manual download may be required)""",
            "source": "awesome-ml-for-cybersecurity",
            "domain": "dataset_knowledge",
            "metadata": {
                "dataset_name": name,
                "dataset_type": info['type'],
                "priority": info['priority']
            }
        })
        
        # Add practical usage sample
        samples.append({
            "instruction": f"How would you use the {name} dataset for training a cybersecurity model?",
            "output": f"""To use the {name} dataset for cybersecurity model training:

## Data Preparation
1. **Download**: Get dataset from {info['url']}
2. **Format**: Parse {info['format'].upper()} format
3. **Clean**: Handle missing values, normalize features
4. **Split**: Train/validation/test (80/10/10)

## Feature Engineering
- Extract relevant features for {info['type'].replace('_', ' ')}
- Handle class imbalance (typically severe in cyber datasets)
- Feature selection using mutual information / chi-square

## Model Training
- **Algorithm**: XGBoost, LightGBM, or Neural Networks
- **Validation**: Stratified k-fold (stratified by attack class)
- **Metrics**: Precision, Recall, F1, AUC-ROC (accuracy misleading)

## Example Code Structure
```python
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Load {name} dataset
df = pd.read_csv('{name}.csv')  # Adjust for format

# Prepare features/target
X = df.drop('label', axis=1)
y = df['label']

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# Train
model = RandomForestClassifier(n_estimators=100, class_weight='balanced')
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))
```

## Common Pitfalls
- **Data leakage**: Ensure temporal splits for time-series data
- **Class imbalance**: Use SMOTE, ADASYN, or class weights
- **Concept drift**: Retrain periodically on new data
- **Feature leakage**: Remove identifiers (IPs, timestamps) that don't generalize""",
            "source": "awesome-ml-for-cybersecurity",
            "domain": "dataset_usage",
            "metadata": {
                "dataset_name": name,
                "dataset_type": info['type']
            }
        })
    
    return samples


def main():
    output_dir = Path("data/awesome_ml_cybersec")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Processing {len(CYBER_DATASETS)} datasets from awesome-ml-for-cybersecurity...")
    
    # Download/process datasets
    for name, info in CYBER_DATASETS.items():
        download_dataset(name, info, output_dir)
    
    # Create training samples
    print("\n" + "="*60)
    print("Creating training samples...")
    samples = create_training_samples(output_dir)
    
    # Save as JSONL for training
    output_file = output_dir / "awesome_ml_cybersec_training.jsonl"
    with open(output_file, 'w') as f:
        for sample in samples:
            f.write(json.dumps(sample) + '\n')
    
    print(f"\n✅ Created {len(samples)} training samples")
    print(f"📁 Output: {output_file}")
    print(f"📁 Dataset metadata: {output_dir}/")
    
    # Summary
    high_priority = [n for n, i in CYBER_DATASETS.items() if i['priority'] == 'high']
    print(f"\n🎯 High-priority datasets ({len(high_priority)}):")
    for n in high_priority:
        print(f"  - {n}: {CYBER_DATASETS[n]['description']}")


if __name__ == "__main__":
    main()