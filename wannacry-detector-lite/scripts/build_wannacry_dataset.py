#!/usr/bin/env python3
"""Build a synthetic ransomware training dataset.

Generates a CSV dataset with 16 feature columns and a label column.
Uses real benign PE files for negative samples and synthetic feature
vectors for WannaCry and BlackCat samples.

Usage:
    python scripts/build_wannacry_dataset.py --benign-dir C:\\Windows\\System32 --output datasets/ransomware_lite.csv
"""

import argparse
import csv
import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.feature_extractor import NUM_FEATURES, extract_features
from core.logger_setup import get_logger, setup_logging

logger = get_logger(__name__)

FEATURE_COLS = [f"feature_{i}" for i in range(1, NUM_FEATURES + 1)]


def generate_wannacry_sample(seed: int) -> list[float]:
    """Generate synthetic feature vector resembling WannaCry characteristics.

    WannaCry features typically show:
        - High entropy (7.0-8.0)
        - High chi-square (>10000)
        - Small byte histogram variance
        - Moderate file size (3.5MB typical)
        - 5 sections
        - High exec ratio
        - Multiple suspicious imports
    """
    rng = random.Random(seed)
    return [
        rng.uniform(6.5, 8.0),
        rng.uniform(6.0, 7.8),
        rng.uniform(5.5, 7.5),
        rng.uniform(8000, 50000),
        rng.uniform(0.0, 0.05),
        rng.uniform(0.0, 0.05),
        rng.uniform(0.0, 0.05),
        rng.uniform(0.0, 0.05),
        rng.uniform(0.0, 0.1),
        rng.uniform(0.0, 0.1),
        rng.uniform(0.0, 0.1),
        rng.uniform(0.3, 1.0),
        math.log2(3.5 * 1024 * 1024 + rng.uniform(-1e5, 1e5)),
        float(rng.choice([4, 5, 6])),
        rng.uniform(0.5, 0.9),
        float(rng.randint(3, 8)),
    ]


def generate_blackcat_sample(seed: int) -> list[float]:
    """Generate synthetic feature vector resembling BlackCat/ALPHV characteristics.

    BlackCat features typically show:
        - Very high entropy (7.0-7.99, Rust binaries are dense)
        - High chi-square (5000-40000)
        - Uniform byte histogram (encrypted/compressed Rust binary)
        - Variable file size (2-8MB)
        - Many sections (6-12, typical of Rust compilation)
        - Moderate exec ratio (0.3-0.7)
        - Many suspicious imports (BCrypt*, process enumeration)
    """
    rng = random.Random(seed)
    return [
        rng.uniform(7.0, 7.99),    # entropy_full: very high (Rust + encryption)
        rng.uniform(6.5, 7.9),     # entropy_text: high
        rng.uniform(5.0, 7.0),     # entropy_data: moderate-high
        rng.uniform(5000, 40000),  # chi_square: high randomness
        rng.uniform(0.0, 0.08),    # hist_0_31: uniform-ish
        rng.uniform(0.0, 0.08),    # hist_32_63
        rng.uniform(0.0, 0.08),    # hist_64_95
        rng.uniform(0.0, 0.08),    # hist_96_127
        rng.uniform(0.0, 0.12),    # hist_128_159
        rng.uniform(0.0, 0.12),    # hist_160_191
        rng.uniform(0.0, 0.12),    # hist_192_223
        rng.uniform(0.2, 0.8),     # hist_224_255
        math.log2(rng.uniform(2e6, 8e6)),  # file_size_log: 2-8MB
        float(rng.choice([6, 7, 8, 9, 10, 11, 12])),  # num_sections: many (Rust)
        rng.uniform(0.3, 0.7),     # exec_ratio: moderate
        float(rng.randint(4, 10)), # suspicious_imports: many BCrypt/process APIs
    ]


def generate_benign_sample(seed: int) -> list[float]:
    """Generate synthetic benign feature vector."""
    rng = random.Random(seed)
    return [
        rng.uniform(3.5, 6.5),
        rng.uniform(3.0, 6.0),
        rng.uniform(2.5, 5.5),
        rng.uniform(1000, 20000),
        rng.uniform(0.0, 0.2),
        rng.uniform(0.0, 0.2),
        rng.uniform(0.0, 0.2),
        rng.uniform(0.0, 0.2),
        rng.uniform(0.0, 0.1),
        rng.uniform(0.0, 0.1),
        rng.uniform(0.0, 0.1),
        rng.uniform(0.0, 0.3),
        math.log2(rng.uniform(5e4, 5e7)),
        float(rng.randint(3, 10)),
        rng.uniform(0.1, 0.5),
        float(rng.randint(0, 2)),
    ]


def build_dataset(
    wannacry_count: int = 500,
    blackcat_count: int = 500,
    benign_count: int = 2000,
    benign_dir: Path | None = None,
) -> list[tuple[list[float], str]]:
    """Build a dataset combining synthetic ransomware and real/synthetic benign samples.

    Args:
        wannacry_count: Number of WannaCry samples to generate.
        blackcat_count: Number of BlackCat samples to generate.
        benign_count: Number of benign samples to generate.
        benign_dir: Optional directory of benign PE files to extract features from.

    Returns:
        List of (feature_vector, label) tuples.
    """
    rows: list[tuple[list[float], str]] = []

    logger.info("Generating %d synthetic WannaCry samples...", wannacry_count)
    for i in range(wannacry_count):
        features = generate_wannacry_sample(i)
        rows.append((features, "wannacry"))

    logger.info("Generating %d synthetic BlackCat samples...", blackcat_count)
    for i in range(blackcat_count):
        features = generate_blackcat_sample(wannacry_count + i)
        rows.append((features, "blackcat"))

    real_benign = 0
    if benign_dir and benign_dir.exists():
        logger.info("Scanning benign directory: %s", benign_dir)
        benign_files = list(benign_dir.rglob("*.exe"))[:benign_count]
        for fp in benign_files:
            try:
                feat = extract_features(fp)
                if feat:
                    arr = [feat[f"feature_{j}"] for j in range(1, NUM_FEATURES + 1)]
                    rows.append((arr, "benign"))
                    real_benign += 1
            except Exception as e:
                logger.debug("Skipping %s: %s", fp, e)
        logger.info("Extracted features from %d real benign files", real_benign)

    synthetic_needed = max(0, benign_count - real_benign)
    logger.info("Generating %d synthetic benign samples...", synthetic_needed)
    for i in range(synthetic_needed):
        features = generate_benign_sample(wannacry_count + blackcat_count + i)
        rows.append((features, "benign"))

    random.shuffle(rows)
    return rows


def save_dataset(rows: list[tuple[list[float], str]], output_path: Path) -> None:
    """Save dataset to CSV.

    Args:
        rows: List of (features, label) tuples.
        output_path: Path to output CSV.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([*FEATURE_COLS, "label"])
        for features, label in rows:
            writer.writerow([*features, label])
    logger.info("Dataset saved to %s (%d rows)", output_path, len(rows))


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Build ransomware training dataset (WannaCry + BlackCat + Benign)"
    )
    parser.add_argument(
        "--wannacry-count",
        type=int,
        default=500,
        help="Number of synthetic WannaCry samples (default: 500)",
    )
    parser.add_argument(
        "--blackcat-count",
        type=int,
        default=500,
        help="Number of synthetic BlackCat samples (default: 500)",
    )
    parser.add_argument(
        "--benign-count",
        type=int,
        default=2000,
        help="Number of benign samples (default: 2000)",
    )
    parser.add_argument(
        "--benign-dir",
        type=Path,
        default=None,
        help="Directory of benign PE files for real feature extraction",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("datasets/ransomware_lite.csv"),
        help="Output CSV path (default: datasets/ransomware_lite.csv)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    setup_logging()
    random.seed(args.seed)

    logger.info("Building ransomware dataset...")
    rows = build_dataset(
        wannacry_count=args.wannacry_count,
        blackcat_count=args.blackcat_count,
        benign_count=args.benign_count,
        benign_dir=args.benign_dir,
    )

    save_dataset(rows, args.output)

    w_count = sum(1 for _, label in rows if label == "wannacry")
    b_count = sum(1 for _, label in rows if label == "blackcat")
    n_count = sum(1 for _, label in rows if label == "benign")
    logger.info(
        "Dataset complete: %d wannacry, %d blackcat, %d benign, %d total",
        w_count, b_count, n_count, len(rows),
    )


if __name__ == "__main__":
    main()
