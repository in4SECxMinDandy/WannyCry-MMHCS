# WannaCry Indicators of Compromise (IOC)

> **Disclaimer**: All IOCs below are sourced from PUBLIC references (CISA, Microsoft, MITRE).
> This document is for ACADEMIC REFERENCE ONLY. No actual malware samples are included.

## File Hashes (SHA256) — Public Reference Only

| Variant | SHA256 |
|---------|--------|
| WannaCry v1 | `ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa` |
| WannaCry v2 | `24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c` |
| Variant 3 | `84c82835a5d21bbcf75a61706d8ab549818553cf4159b46e5f27c672f6b924a8` |
| Variant 4 | `db349b97c37d22f5ea1d1841e3c89eb4e2b1c39b4b5b3d22f16c40a16515d13c` |

Source: [CISA Alert TA17-132A](https://www.cisa.gov/uscert/ncas/alerts/TA17-132A)

## Mutex

| Mutex Name | Purpose |
|------------|---------|
| `MsWinZonesCacheCounterMutexA` | Prevent multiple WannaCry instances running simultaneously |
| `Global\MsWinZonesCacheCounterMutexA` | Global mutex variant |

## Killswitch Domain

| Domain |
|--------|
| `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com` |
| `www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com` |

Discovery by [@MalwareTechBlog](https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html)

## File Extensions

| Extension | Description |
|-----------|-------------|
| `.wncry` | Primary encrypted file extension |
| `.WNCRY` | Uppercase variant |
| `.WNCRYT` | Temporary encrypted file extension |
| `.wcry` | Alternative extension |

## Ransom Note Files

| Filename |
|----------|
| `@Please_Read_Me@.txt` |
| `@WanaDecryptor@.exe` |
| `!Please Read Me!.hta` |
| `WanaDecryptor.exe` |

## Process Names

| Process | Description |
|---------|-------------|
| `tasksche.exe` | Main WannaCry dropper |
| `@WanaDecryptor@.exe` | Encryption/decryption module |
| `WanaDecryptor.exe` | GUI ransom note |

## Registry Keys

| Key | Description |
|-----|-------------|
| `HKLM\SOFTWARE\WanaCrypt0r` | Installed flag |
| `HKCU\Software\WanaCrypt0r` | Per-user settings |

## Strings in Binary

| String | Context |
|--------|---------|
| `WANACRY!` | Program marker |
| `Wanna Decryptor` | Ransom note title |
| `WanaCrypt0r` | Internal name |
| `wcry@123` | Password reference |
| `TaskStart` | Task scheduler string |

## Exploitation

| Exploit | CVE | Description |
|---------|-----|-------------|
| EternalBlue | CVE-2017-0144 | SMBv1 remote code execution (MS17-010) |
| DoublePulsar | - | Backdoor implant used with EternalBlue |

## Network Indicators

| Protocol | Port | Description |
|----------|------|-------------|
| SMB | 445 | EternalBlue exploit target |

## Filesystem Behavior

- Encrypts user files with AES-128 + RSA-2048
- Appends `.wncry` extension to encrypted files
- Creates `@Please_Read_Me@.txt` in each affected directory
- Drops `@WanaDecryptor@.exe` for ransom payment interface
- Uses Tor network for C2 communication (hardcoded .onion addresses)

## References

1. [MITRE ATT&CK S0366 - WannaCry](https://attack.mitre.org/software/S0366/)
2. [CISA Alert TA17-132A - Indicators Associated With WannaCry Ransomware](https://www.cisa.gov/uscert/ncas/alerts/TA17-132A)
3. [Microsoft Security Response Center - WannaCrypt attacks](https://www.microsoft.com/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/)
4. [US-CERT - MS17-010 SMB Vulnerability](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
5. [MalwareTech - How to Accidentally Stop a Global Cyber Attack](https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html)

---

*Last updated: 2024 | For academic reference only*
