"""Feature extraction from PE files for WannaCry detection.

Extracts 16 features used by the Random Forest ML engine.
"""

import math
from collections import Counter
from pathlib import Path

import pefile

from core.logger_setup import get_logger

logger = get_logger(__name__)

NUM_FEATURES = 16
NUM_BINS = 8
BIN_SIZE = 256 // NUM_BINS

SUSPICIOUS_IMPORTS = {
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptGenRandom",
    "CryptAcquireContextW",
    "FindFirstFileW",
    "FindNextFileW",
    "MoveFileExW",
    "InternetOpenA",
    "InternetOpenUrlA",
    "InternetReadFile",
    "WinExec",
    "ShellExecuteA",
    "CreateRemoteThread",
    "WriteProcessMemory",
}


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    length = len(data)
    counter = Counter(data)
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _chi_square(data: bytes) -> float:
    """Calculate chi-square statistic for byte distribution uniformity."""
    if not data:
        return 0.0
    length = len(data)
    expected = length / 256
    counter = Counter(data)
    chi2 = 0.0
    for byte_val in range(256):
        observed = counter.get(byte_val, 0)
        diff = observed - expected
        if expected > 0:
            chi2 += (diff * diff) / expected
    return chi2


def _byte_histogram_bins(data: bytes) -> list[float]:
    """Build 8-bin histogram of byte distribution (0-31, 32-63, ..., 224-255)."""
    if not data:
        return [0.0] * NUM_BINS
    counter = Counter(data)
    length = len(data)
    bins = [0.0] * NUM_BINS
    for byte_val, count in counter.items():
        bin_idx = min(byte_val // BIN_SIZE, NUM_BINS - 1)
        bins[bin_idx] += count / length
    return bins


def extract_features(file_path: Path) -> dict[str, float] | None:
    """Extract 16 numeric features from a PE file.

    Args:
        file_path: Path to the PE file.

    Returns:
        Dictionary with keys feature_1 through feature_16, or None if extraction fails.
    """
    file_path = Path(file_path)
    try:
        with open(file_path, "rb") as f:
            raw_data = f.read()
    except (OSError, PermissionError) as e:
        logger.warning("Cannot read file %s: %s", file_path, e)
        return None

    if len(raw_data) < 64:
        logger.debug("File %s too small to be PE", file_path)
        return None

    try:
        pe = pefile.PE(data=raw_data, fast_load=True)
    except pefile.PEFormatError:
        logger.debug("File %s is not a valid PE", file_path)
        return None

    full_entropy = _shannon_entropy(raw_data)

    text_entropy = 0.0
    data_entropy = 0.0
    exec_size = 0
    try:
        for section in pe.sections:
            section_data = section.get_data()
            section_name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
            if section_name == ".text":
                text_entropy = _shannon_entropy(section_data)
            elif section_name == ".data":
                data_entropy = _shannon_entropy(section_data)
            if section.Characteristics & 0x20000000:
                exec_size += len(section_data)
    except Exception:
        pass

    chi2 = _chi_square(raw_data)
    hist_bins = _byte_histogram_bins(raw_data)
    file_size_log = math.log2(max(len(raw_data), 1))
    num_sections = len(pe.sections)
    total_size = len(raw_data)
    exec_ratio = exec_size / max(total_size, 1)

    suspicious_count = 0
    try:
        pe_full = pefile.PE(data=raw_data)
        if hasattr(pe_full, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe_full.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode("ascii", errors="ignore") in SUSPICIOUS_IMPORTS:
                        suspicious_count += 1
    except Exception:
        pass

    features = {
        "feature_1": full_entropy,
        "feature_2": text_entropy,
        "feature_3": data_entropy,
        "feature_4": chi2,
        "feature_5": hist_bins[0],
        "feature_6": hist_bins[1],
        "feature_7": hist_bins[2],
        "feature_8": hist_bins[3],
        "feature_9": hist_bins[4],
        "feature_10": hist_bins[5],
        "feature_11": hist_bins[6],
        "feature_12": hist_bins[7],
        "feature_13": file_size_log,
        "feature_14": float(num_sections),
        "feature_15": exec_ratio,
        "feature_16": float(suspicious_count),
    }

    pe.close()
    return features


def features_to_array(features: dict[str, float]) -> list[float]:
    """Convert features dict to ordered array for model inference.

    Args:
        features: Dictionary from extract_features.

    Returns:
        List of 16 float values in order feature_1 through feature_16.
    """
    return [features[f"feature_{i}"] for i in range(1, NUM_FEATURES + 1)]


def get_feature_names() -> list[str]:
    """Return ordered list of feature names."""
    return [
        "entropy_full",
        "entropy_text",
        "entropy_data",
        "chi_square",
        "hist_bin_0_31",
        "hist_bin_32_63",
        "hist_bin_64_95",
        "hist_bin_96_127",
        "hist_bin_128_159",
        "hist_bin_160_191",
        "hist_bin_192_223",
        "hist_bin_224_255",
        "file_size_log",
        "num_sections",
        "exec_ratio",
        "suspicious_imports",
    ]
