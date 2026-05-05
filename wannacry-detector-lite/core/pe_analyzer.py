"""PE file analysis module for ransomware-specific indicators (WannaCry & BlackCat)."""

from pathlib import Path

import pefile

from core.logger_setup import get_logger

logger = get_logger(__name__)

WANNACRY_SECTIONS = {".wnry", ".wncry"}
PACKER_SIGNS = {"UPX", "ASPack", "MPRESS", "PECompact", "Themida", "VMProtect", "Enigma"}
NORMAL_SECTIONS = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss", ".idata", ".edata"}

WANNACRY_IMPORTS = {
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptGenRandom",
    "CryptAcquireContextW",
    "FindFirstFileW",
    "FindNextFileW",
    "MoveFileExW",
    "InternetOpenA",
    "InternetOpenUrlA",
}

BLACKCAT_IMPORTS = {
    "BCryptEncrypt",
    "BCryptDecrypt",
    "BCryptGenerateSymmetricKey",
    "BCryptOpenAlgorithmProvider",
    "NtSetInformationProcess",
    "RtlAdjustPrivilege",
    "CreateToolhelp32Snapshot",
    "Process32First",
    "Process32Next",
    "TerminateProcess",
}

RUST_INDICATORS = {
    "rust_panic",
    "rust_begin_unwind",
    "_ZN3std",
    "core::panicking",
    "alloc::raw_vec",
}


class PEResult:
    """Result of PE analysis."""

    def __init__(self) -> None:
        self.is_pe: bool = False
        self.is_packed: bool = False
        self.packer_hint: str | None = None
        self.num_sections: int = 0
        self.section_names: list[str] = []
        self.has_wannacry_section: bool = False
        self.has_suspicious_imports: bool = False
        self.suspicious_imports: list[str] = []
        self.suspicion_score: float = 0.0
        # BlackCat-specific fields
        self.has_blackcat_indicators: bool = False
        self.blackcat_imports: list[str] = []
        self.is_rust_binary: bool = False
        self.detected_family: str | None = None


def _detect_packer(pe: pefile.PE) -> tuple[bool, str | None]:
    """Heuristic packer detection based on section names and characteristics.

    Args:
        pe: Parsed pefile.PE object.

    Returns:
        Tuple of (is_packed, packer_hint).
    """
    section_names = set()
    for section in pe.sections:
        try:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
            section_names.add(name)
        except Exception:
            pass

    for packer in PACKER_SIGNS:
        if packer.lower() in {n.lower() for n in section_names}:
            return True, packer

    odd_sections = section_names - NORMAL_SECTIONS
    if odd_sections:
        for s in odd_sections:
            if len(s) > 8:
                return True, None

    if len(pe.sections) <= 2:
        _ = pe.get_memory_mapped_image()

    return False, None


def _detect_rust_binary(pe: pefile.PE, raw_data: bytes) -> bool:
    """Heuristic detection of Rust-compiled binary.

    Args:
        pe: Parsed pefile.PE object.
        raw_data: Raw file bytes.

    Returns:
        True if binary appears to be compiled with Rust.
    """
    # Check for Rust-specific strings in raw data
    for indicator in RUST_INDICATORS:
        if indicator.encode("ascii") in raw_data:
            return True

    # Rust binaries typically have many sections and large .rdata
    rdata_size = 0
    for section in pe.sections:
        try:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
            if name == ".rdata":
                rdata_size = section.SizeOfRawData
        except Exception:
            pass

    # Rust binaries tend to have large .rdata relative to file size
    if rdata_size > 0 and len(raw_data) > 0:
        if rdata_size / len(raw_data) > 0.3 and len(pe.sections) >= 6:
            return True

    return False


def analyze(file_path: Path) -> PEResult:
    """Analyze a PE file for ransomware indicators (WannaCry & BlackCat).

    Args:
        file_path: Path to executable file.

    Returns:
        PEResult with analysis findings.
    """
    result = PEResult()

    try:
        with open(file_path, "rb") as f:
            raw_data = f.read()
    except (OSError, PermissionError) as e:
        logger.warning("Cannot read file %s: %s", file_path, e)
        return result

    if len(raw_data) < 64:
        return result

    try:
        pe = pefile.PE(data=raw_data)
    except pefile.PEFormatError:
        return result

    result.is_pe = True
    result.num_sections = len(pe.sections)

    for section in pe.sections:
        try:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
            if name:
                result.section_names.append(name)
                if name in WANNACRY_SECTIONS:
                    result.has_wannacry_section = True
        except Exception:
            pass

    result.is_packed, result.packer_hint = _detect_packer(pe)

    # Detect Rust binary (BlackCat indicator)
    result.is_rust_binary = _detect_rust_binary(pe, raw_data)

    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        try:
                            name = imp.name.decode("ascii", errors="ignore")
                        except Exception:
                            name = str(imp.name)
                        if name in WANNACRY_IMPORTS:
                            result.suspicious_imports.append(name)
                            result.has_suspicious_imports = True
                        if name in BLACKCAT_IMPORTS:
                            result.blackcat_imports.append(name)
                            result.has_blackcat_indicators = True
    except Exception as e:
        logger.debug("Import parsing failed for %s: %s", file_path, e)

    # Check for BlackCat string indicators in raw data
    blackcat_string_indicators = [
        b"encrypt_app", b"locker::core", b"::pipeline::file_worker_pool",
    ]
    for indicator in blackcat_string_indicators:
        if indicator in raw_data:
            result.has_blackcat_indicators = True
            break

    # Score calculation — WannaCry indicators
    wannacry_score = 0.0
    if result.has_wannacry_section:
        wannacry_score += 0.4
    if result.has_suspicious_imports:
        wannacry_score += min(len(result.suspicious_imports) * 0.1, 0.3)
    if result.is_packed:
        wannacry_score += 0.2
    if result.num_sections < 3 and result.is_pe:
        wannacry_score += 0.1

    # Score calculation — BlackCat indicators
    blackcat_score = 0.0
    if result.is_rust_binary:
        blackcat_score += 0.3
    if result.has_blackcat_indicators:
        blackcat_score += min(len(result.blackcat_imports) * 0.1, 0.3)
    if result.has_blackcat_indicators and not result.blackcat_imports:
        blackcat_score += 0.2  # String indicators without specific imports
    if result.num_sections >= 8 and result.is_rust_binary:
        blackcat_score += 0.2

    # Use the higher score as the overall suspicion score
    result.suspicion_score = min(max(wannacry_score, blackcat_score), 1.0)

    # Determine detected family based on strongest signal
    if blackcat_score > wannacry_score and blackcat_score >= 0.3:
        result.detected_family = "blackcat"
    elif wannacry_score >= 0.3:
        result.detected_family = "wannacry"

    pe.close()
    return result
