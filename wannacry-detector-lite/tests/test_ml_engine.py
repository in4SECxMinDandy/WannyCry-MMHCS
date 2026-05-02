"""Tests for ML engine module."""

from pathlib import Path

import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from core.ml_engine import MLEngine


@pytest.fixture
def dummy_model(tmp_path: Path) -> Path:
    """Train a tiny Random Forest model for testing."""
    rng = np.random.RandomState(42)
    X = rng.randn(100, 16)
    y = np.array([0] * 80 + [1] * 20)
    model = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=42)
    model.fit(X, y)
    model_path = tmp_path / "test_model.pkl"
    joblib.dump(model, model_path)
    return model_path


@pytest.fixture
def wannacry_features() -> dict[str, float]:
    """Features resembling WannaCry."""
    return {
        "feature_1": 7.5,
        "feature_2": 6.8,
        "feature_3": 6.2,
        "feature_4": 25000.0,
        "feature_5": 0.01,
        "feature_6": 0.01,
        "feature_7": 0.02,
        "feature_8": 0.03,
        "feature_9": 0.04,
        "feature_10": 0.05,
        "feature_11": 0.1,
        "feature_12": 0.74,
        "feature_13": 21.8,
        "feature_14": 5.0,
        "feature_15": 0.7,
        "feature_16": 5.0,
    }


class TestMLEngine:
    def test_load_model(self, dummy_model) -> None:
        engine = MLEngine(model_path=dummy_model)
        assert engine.is_loaded()

    def test_load_nonexistent_model(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            MLEngine(model_path=tmp_path / "no_model.pkl")

    def test_predict_returns_label_and_score(self, dummy_model, wannacry_features) -> None:
        engine = MLEngine(model_path=dummy_model)
        label, score = engine.predict(wannacry_features)
        assert label in ("wannacry", "benign")
        assert 0.0 <= score <= 1.0

    def test_predict_with_different_threshold(self, dummy_model, wannacry_features) -> None:
        engine_low = MLEngine(model_path=dummy_model, threshold=0.3)
        engine_high = MLEngine(model_path=dummy_model, threshold=0.99)
        label_low, _ = engine_low.predict(wannacry_features)
        label_high, _ = engine_high.predict(wannacry_features)
        assert label_low in ("wannacry", "benign")
        assert label_high in ("wannacry", "benign")

    def test_predict_without_model(self, tmp_path) -> None:
        engine = MLEngine.__new__(MLEngine)
        engine._model = None
        engine.model_path = tmp_path / "none.pkl"
        engine.threshold = 0.7
        with pytest.raises(RuntimeError):
            engine.predict({"feature_1": 1.0})
