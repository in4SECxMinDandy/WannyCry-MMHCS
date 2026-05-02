"""PE file analysis module for WannaCry-specific indicators."""

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


def analyze(file_path: Path) -> PEResult:
    """Analyze a PE file for WannaCry indicators.

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
    except Exception as e:
        logger.debug("Import parsing failed for %s: %s", file_path, e)

    score = 0.0
    if result.has_wannacry_section:
        score += 0.4
    if result.has_suspicious_imports:
        score += min(len(result.suspicious_imports) * 0.1, 0.3)
    if result.is_packed:
        score += 0.2
    if result.num_sections < 3 and result.is_pe:
        score += 0.1

    result.suspicion_score = min(score, 1.0)
    pe.close()
    return result
