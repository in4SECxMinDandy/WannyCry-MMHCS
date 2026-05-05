/*
 * BlackCat (ALPHV) Detection Rules
 *
 * References:
 *   - MITRE ATT&CK S1068 (BlackCat)
 *   - FBI/CISA #StopRansomware: BlackCat/ALPHV (AA23-353A)
 *   - SentinelOne BlackCat Technical Analysis
 */

rule BlackCat_Rust_Strings {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects Rust module paths characteristic of BlackCat/ALPHV binaries"
        reference = "https://attack.mitre.org/software/S1068/"
        severity = "high"
    strings:
        $rs1 = "encrypt_app::windows" ascii wide
        $rs2 = "encrypt_app::linux" ascii wide
        $rs3 = "locker::core::" ascii wide
        $rs4 = "src/bin/encrypt_app/app.rs" ascii wide
        $rs5 = "library/encrypt-lib/src/app.rs" ascii wide
        $rs6 = "::pipeline::file_worker_pool" ascii wide
        $rs7 = "set_desktop_image::" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule BlackCat_Config_Strings {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects embedded JSON configuration patterns used by BlackCat"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a"
        severity = "high"
    strings:
        $cfg1 = "config_id" ascii wide
        $cfg2 = "pub_key" ascii wide
        $cfg3 = "extension" ascii wide
        $cfg4 = "note_file_name" ascii wide
        $cfg5 = "credentials" ascii wide
        $cfg6 = "--access-token" ascii wide
        $cfg7 = "--child" ascii wide
        $rust_panic = "rust_panic" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($rust_panic or 3 of ($cfg*))
}

rule BlackCat_Anti_Recovery {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects shadow copy deletion and recovery disabling commands"
        reference = "https://attack.mitre.org/techniques/T1490/"
        severity = "critical"
    strings:
        $cmd1 = "vssadmin delete shadows" ascii wide nocase
        $cmd2 = "vssadmin.exe delete shadows" ascii wide nocase
        $cmd3 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $cmd4 = "wmic shadowcopy delete" ascii wide nocase
        $cmd5 = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii wide nocase
        $svc1 = "enum_dependent_services" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule BlackCat_Ransom_Note {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects BlackCat ransom note filename patterns"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a"
        severity = "medium"
    strings:
        $note1 = "RECOVER-" ascii wide nocase
        $note2 = "-FILES.txt" ascii wide nocase
        $note3 = ".onion" ascii wide
        $note4 = "What happened?" ascii wide nocase
        $note5 = "Important files" ascii wide nocase
        $note6 = "encrypted" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        ($note1 and $note2) or
        (3 of ($note*) and $note3)
}

rule BlackCat_UAC_Bypass {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects UAC bypass and privilege escalation strings"
        reference = "https://attack.mitre.org/techniques/T1548/002/"
        severity = "high"
    strings:
        $uac1 = "uac_bypass::shell_exec" ascii wide
        $uac2 = "::os::windows::privilege_escalation" ascii wide
        $uac3 = "hidden_partitions::mount_all" ascii wide
        $uac4 = "masquerade_peb" ascii wide
        $uac5 = "cmstplua" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule BlackCat_PsExec_Spread {
    meta:
        author = "PTIT Security Research Lab"
        description = "Detects PsExec-based lateral movement patterns used by BlackCat"
        reference = "https://attack.mitre.org/techniques/T1569/002/"
        severity = "high"
    strings:
        $ps1 = "psexec_args=" ascii wide
        $ps2 = "::os::windows::netbios" ascii wide
        $ps3 = "propagate::" ascii wide
        $ps4 = "PsExec" ascii wide nocase
        $ps5 = "wmiexec" ascii wide nocase
        $net1 = "\\\\pipe\\__rust_anonymous_pipe" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
