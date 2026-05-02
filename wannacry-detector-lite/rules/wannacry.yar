/*
 * WannaCry Detection Rules
 * 
 * References:
 *   - MITRE ATT&CK S0366 (WannaCry)
 *   - US-CERT Alert TA17-132A
 *   - Microsoft Malware Protection Center
 */

rule WannaCry_Strings {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects WannaCry-specific strings in binaries"
        reference = "https://attack.mitre.org/software/S0366/"
        severity = "high"
    strings:
        $s1 = "WANACRY!" ascii wide nocase
        $s2 = "Wanna Decryptor" ascii wide nocase
        $s3 = ".wncry" ascii wide
        $s4 = "@WanaDecryptor@" ascii wide
        $s5 = "tasksche.exe" ascii wide nocase
        $s6 = "TaskStart" ascii wide
        $s7 = "wcry@123" ascii wide
        $s8 = "WanaCrypt0r" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule WannaCry_Killswitch {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects WannaCry killswitch domain reference"
        reference = "https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html"
        severity = "critical"
    strings:
        $domain1 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide
        $domain2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide
        $domain3 = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule WannaCry_Mutex {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects WannaCry mutex name to prevent multiple instances"
        reference = "https://www.cisa.gov/uscert/ncas/alerts/TA17-132A"
        severity = "high"
    strings:
        $mutex1 = "MsWinZonesCacheCounterMutexA" ascii wide
        $mutex2 = "MsWinZonesCacheCounterMutex0" ascii wide
        $mutex3 = "Global\\MsWinZonesCacheCounterMutexA" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule WannaCry_Crypto_Imports {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects combination of crypto API imports and .wnry section"
        reference = "https://attack.mitre.org/software/S0366/"
        severity = "high"
    strings:
        $import1 = "CryptEncrypt" ascii wide
        $import2 = "CryptDecrypt" ascii wide
        $import3 = "CryptGenRandom" ascii wide
        $import4 = "CryptAcquireContext" ascii wide
        $import5 = "CryptImportKey" ascii wide
        $import6 = "CryptExportKey" ascii wide
        $import7 = "CryptDestroyKey" ascii wide
        $import8 = "FindFirstFileW" ascii wide
        $import9 = "FindNextFileW" ascii wide
        $import10 = "MoveFileExW" ascii wide
        $section = ".wnry"
        $ext = ".wncry"
    condition:
        uint16(0) == 0x5A4D and
        (4 of ($import*)) and
        (any of ($section, $ext))
}

rule WannaCry_Ransom_Note {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects references to WannaCry ransom note files"
        reference = "https://www.cisa.gov/uscert/ncas/alerts/TA17-132A"
        severity = "high"
    strings:
        $note1 = "@Please_Read_Me@.txt" ascii wide nocase
        $note2 = "@WanaDecryptor@.exe" ascii wide nocase
        $note3 = "!Please Read Me!.hta" ascii wide nocase
        $note4 = "Please Read Me!.txt" ascii wide nocase
        $note5 = "WanaDecryptor.exe" ascii wide nocase
        $note6 = "WanaDecryptor!.exe" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule WannaCry_File_Extension {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects references to WannaCry encrypted file extensions"
        reference = "https://attack.mitre.org/software/S0366/"
        severity = "medium"
    strings:
        $wcry1 = ".WNCRY" wide ascii
        $wcry2 = ".wcry" wide ascii
        $wcry3 = ".WNCRYT" wide ascii
        $wcry4 = ".WNCYRT" wide ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule WannaCry_SMB_Exploit {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects SMB exploit strings used by WannaCry (EternalBlue)"
        reference = "https://attack.mitre.org/software/S0366/"
        severity = "critical"
    strings:
        $smb1 = "EternalBlue" wide ascii nocase
        $smb2 = "DoublePulsar" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}
