# Sample Collection Guide

## Academic Disclaimer
This tool is for **academic and research purposes only**. Do NOT use real malware
samples without proper isolation (air-gapped VM, sandbox). The project provides
synthetic dataset generation for training.

## Option 1: Synthetic Dataset (Recommended)

Run the built-in script to generate a fully synthetic dataset:

```bash
python scripts/build_wannacry_dataset.py \
    --wannacry-count 500 \
    --benign-count 2000 \
    --output datasets/wannacry_lite.csv
```

This creates realistic feature vectors mimicking WannaCry characteristics
(high entropy, many crypto imports, large .text section ratio) and benign
files. The dataset works out-of-the-box for training.

## Option 2: Mix with Real Benign Files

To improve model robustness with real benign features:

```bash
python scripts/build_wannacry_dataset.py \
    --benign-dir "C:\Windows\System32" \
    --output datasets/wannacry_lite.csv
```

This extracts real PE features from Windows system files as benign examples.

## Option 3: Real WannaCry Samples (Legal Sources Only)

If you have legitimate access to WannaCry samples for research:
1. Use sources like VirusShare, MalShare, or theZoo (academic license required)
2. Extract features with: `python scripts/extract_features.py <sample_dir>`
3. Merge with benign dataset manually

**NEVER run live malware outside a properly isolated environment.**

## Known WannaCry Hashes (Reference Only)

These SHA256 hashes are public knowledge from CISA/Microsoft advisories.
Do NOT store these in the repository. Use only for cross-reference:

- ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa (v1)
- 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c (v2)
- 84c82835a5d21bbcf75a61706d8ab549818553cf4159b46e5f27c672f6b924a8
- db349b97c37d22f5ea1d1841e3c89eb4e2b1c39b4b5b3d22f16c40a16515d13c

Reference: https://www.cisa.gov/uscert/ncas/alerts/TA17-132A
