# Architecture — WannaCry Detector Lite

## 3-Layer Detection Pipeline

```
                          +------------------+
                          |   Target Path    |
                          | (file/directory) |
                          +--------+---------+
                                   |
                                   v
                          +--------+---------+
                          |   Path Walker    |
                          |  (scanner.py)    |
                          +--------+---------+
                                   |
                                   v
                          +--------+---------+
                          |  Whitelist Check |
                          |  (fp_reducer.py) |
                          +--------+---------+
                                   |
                    +--------------+--------------+
                    |              |              |
                    v              v              v
          +---------+--+  +-------+------+  +-------+------+
          | ML Engine   |  | PE Analyzer  |  | YARA Engine  |
          | (ml_engine) |  | (pe_analyzer)|  | (yara_engine)|
          +--------+----+  +------+-------+  +------+-------+
                   |              |                 |
                   |  16 features | suspection      | rule matches
                   |  score       | score           |
                   v              v                 v
          +--------+--------------+-----------------+
          |          Verdict Combiner               |
          |    (_combine_verdict in scanner.py)     |
          +--------+-----------------+--------------+
                   |                 |
                   v                 v
          +--------+------+  +------+--------+
          | ScanResult[]   |  | Report Gen   |
          |                |  | (CSV/JSON/PDF)|
          +----------------+  +---------------+
```

## Detection Rules

| Signal | Weight | Source |
|--------|--------|--------|
| YARA match (any) | verdict = "wannacry" | yara_engine.py |
| ML score >= threshold + PE score >= 0.3 | verdict = "wannacry" | scanner.py |
| ML score >= threshold + PE score < 0.3 | verdict = "suspicious" | scanner.py |
| PE score >= 0.6 alone | verdict = "suspicious" | scanner.py |
| ML borderline (>= 0.8 * threshold) | verdict = "suspicious" | scanner.py |
| All low | verdict = "benign" | scanner.py |

## Feature Extraction (16 features)

1. `feature_1`: Shannon entropy — full file
2. `feature_2`: Shannon entropy — .text section
3. `feature_3`: Shannon entropy — .data section
4. `feature_4`: Chi-square byte distribution
5-12. `feature_5` through `feature_12`: 8-bin byte histogram (0-31, 32-63, ..., 224-255)
13. `feature_13`: File size (log-scaled)
14. `feature_14`: Number of PE sections
15. `feature_15`: Executable section size ratio
16. `feature_16`: Number of suspicious crypto/file imports

## YARA Rules (wannacry.yar)

| Rule | Target IOC |
|------|-----------|
| `WannaCry_Strings` | "WANACRY!", "Wanna Decryptor", ".wncry", "@WanaDecryptor@" |
| `WannaCry_Killswitch` | Domain: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com |
| `WannaCry_Mutex` | Mutex: MsWinZonesCacheCounterMutexA |
| `WannaCry_Crypto_Imports` | Crypto API imports + .wnry section |
| `WannaCry_Ransom_Note` | Ransom note file references |
| `WannaCry_File_Extension` | Encrypted file extensions |
| `WannaCry_SMB_Exploit` | EternalBlue/DoublePulsar references |

## Data Flow

```
User Input -> CLI/GUI -> Scanner.scan_path()
    -> _walk_directory() -> collect files
    -> _analyze_file() per file:
        1. feature_extractor.extract_features()
        2. ml_engine.predict(features) -> (label, score)
        3. pe_analyzer.analyze(file) -> suspicion_score
        4. yara_engine.scan_file(file) -> [matches]
        5. _combine_verdict() -> final verdict
    -> ReportGenerator -> CSV/JSON/PDF output
```
