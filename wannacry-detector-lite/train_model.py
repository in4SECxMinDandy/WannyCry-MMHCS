#!/usr/bin/env python3
"""Train a Random Forest classifier for ransomware detection.

Expects a CSV dataset with columns feature_1..feature_16 and label.
The label column should contain "wannacry", "blackcat", or "benign".

Usage:
    python train_model.py --dataset datasets/ransomware_lite.csv --output models/wannacry_rf.pkl
"""

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder

from core.feature_extractor import NUM_FEATURES
from core.logger_setup import get_logger, setup_logging

logger = get_logger(__name__)

FEATURE_COLS = [f"feature_{i}" for i in range(1, NUM_FEATURES + 1)]


def load_dataset(dataset_path: Path) -> tuple[np.ndarray, np.ndarray]:
    """Load dataset from CSV file.

    Args:
        dataset_path: Path to CSV file.

    Returns:
        Tuple of (X, y) arrays.

    Raises:
        FileNotFoundError: If dataset not found.
        ValueError: If dataset is empty or missing required columns.
    """
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)

    missing_cols = set(FEATURE_COLS) - set(df.columns)
    if missing_cols:
        raise ValueError(f"Dataset missing columns: {missing_cols}")

    if "label" not in df.columns:
        raise ValueError("Dataset missing 'label' column")

    X = df[FEATURE_COLS].fillna(0).values.astype(np.float32)
    y = df["label"].values

    # Encode labels: benign=0, blackcat=1, wannacry=2 (alphabetical order)
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    label_counts = {label: int((y == label).sum()) for label in le.classes_}
    logger.info("Dataset loaded: %d samples, labels: %s", len(X), label_counts)
    return X, y_encoded, le


def train_model(
    dataset_path: Path,
    output_path: Path,
    n_estimators: int = 200,
    max_depth: int = 20,
    test_size: float = 0.2,
    seed: int = 42,
) -> RandomForestClassifier:
    """Train Random Forest model for ransomware detection.

    Args:
        dataset_path: Path to training dataset CSV.
        output_path: Path to save trained model.
        n_estimators: Number of trees in forest.
        max_depth: Maximum tree depth.
        test_size: Fraction for test split.
        seed: Random seed.

    Returns:
        Trained RandomForestClassifier.
    """
    X, y, le = load_dataset(dataset_path)
    target_names = list(le.classes_)

    # Check if SMOTE is needed for any minority class
    unique, counts = np.unique(y, return_counts=True)
    min_count = counts.min()
    if min_count >= 6:  # SMOTE needs at least k_neighbors+1 samples
        logger.info(
            "Class distribution: %s. Applying SMOTE.",
            dict(zip(target_names, [int(c) for c in counts], strict=False)),
        )
        try:
            k_neighbors = min(5, min_count - 1)
            smote = SMOTE(random_state=seed, k_neighbors=k_neighbors)
            X, y = smote.fit_resample(X, y)
            new_unique, new_counts = np.unique(y, return_counts=True)
            logger.info(
                "After SMOTE: %d samples, distribution: %s",
                len(X),
                dict(zip(target_names, [int(c) for c in new_counts], strict=False)),
            )
        except ValueError as e:
            logger.warning("SMOTE failed: %s. Skipping.", e)
    else:
        logger.info("Too few samples for SMOTE (min class has %d). Skipping.", min_count)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )

    logger.info("Training Random Forest (%d trees, max_depth=%d)...", n_estimators, max_depth)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    logger.info("\n%s", classification_report(y_test, y_pred, target_names=target_names))
    logger.info("Confusion Matrix:\n%s", confusion_matrix(y_test, y_pred))

    try:
        cv_scores = cross_val_score(model, X, y, cv=min(5, len(X) // 10))
        logger.info("Cross-validation scores: %s (mean=%.4f)", cv_scores, cv_scores.mean())
    except Exception as e:
        logger.warning("Cross-validation skipped: %s", e)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    logger.info("Model saved to %s", output_path)

    feature_importances = model.feature_importances_
    logger.info("Top 5 features by importance:")
    names = [
        "entropy_full", "entropy_text", "entropy_data", "chi_square",
        "hist_0_31", "hist_32_63", "hist_64_95", "hist_96_127",
        "hist_128_159", "hist_160_191", "hist_192_223", "hist_224_255",
        "file_size_log", "num_sections", "exec_ratio", "suspicious_imports",
    ]
    for idx in np.argsort(feature_importances)[::-1][:5]:
        logger.info("  %s: %.4f", names[idx], feature_importances[idx])

    return model


def main() -> None:
    """CLI entry point for model training."""
    parser = argparse.ArgumentParser(
        description="Train ransomware detection Random Forest model"
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("datasets/ransomware_lite.csv"),
        help="Path to training dataset CSV (default: datasets/ransomware_lite.csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("models/wannacry_rf.pkl"),
        help="Path to save trained model (default: models/wannacry_rf.pkl)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=200,
        help="Number of trees in Random Forest (default: 200)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=20,
        help="Maximum tree depth (default: 20)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    setup_logging()
    logger.info("=" * 60)
    logger.info("Ransomware Detector Lite — Model Training")
    logger.info("=" * 60)

    train_model(
        dataset_path=args.dataset,
        output_path=args.output,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
