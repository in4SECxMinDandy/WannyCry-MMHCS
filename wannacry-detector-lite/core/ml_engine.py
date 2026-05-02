"""Machine learning engine for WannaCry detection via Random Forest."""

from pathlib import Path

import joblib
import numpy as np

from core.feature_extractor import features_to_array
from core.logger_setup import get_logger

logger = get_logger(__name__)


class MLEngine:
    """Random Forest-based WannaCry detection engine."""

    def __init__(self, model_path: Path, threshold: float = 0.7) -> None:
        """Initialize ML engine.

        Args:
            model_path: Path to trained model file (.pkl).
            threshold: Confidence threshold for WannaCry classification.

        Raises:
            FileNotFoundError: If model file does not exist.
        """
        self.model_path = Path(model_path)
        self.threshold = threshold
        self._model = self._load_model()

    def _load_model(self):
        """Load model from disk.

        Returns:
            Trained model object.

        Raises:
            FileNotFoundError: If model file not found.
        """
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Model not found at {self.model_path}. "
                "Run 'python train_model.py' to train a model first."
            )
        try:
            model = joblib.load(self.model_path)
            logger.info("Model loaded from %s", self.model_path)
            return model
        except Exception as e:
            logger.error("Failed to load model from %s: %s", self.model_path, e)
            raise

    def predict(self, features: dict[str, float]) -> tuple[str, float]:
        """Predict whether features indicate WannaCry.

        Args:
            features: Dictionary of feature_1 through feature_16 from feature_extractor.

        Returns:
            Tuple of (label, score) where label is "wannacry" or "benign".

        Raises:
            RuntimeError: If model is not loaded.
        """
        if self._model is None:
            raise RuntimeError("Model not loaded")

        arr = np.array([features_to_array(features)], dtype=np.float32)

        if hasattr(self._model, "predict_proba"):
            proba = self._model.predict_proba(arr)[0]
            classes = self._model.classes_
            wannacry_idx = -1
            for i, cls in enumerate(classes):
                if str(cls).lower() in ("wannacry", "1", "malicious"):
                    wannacry_idx = i
                    break
            if wannacry_idx >= 0:
                score = float(proba[wannacry_idx])
            else:
                score = 1.0 - float(proba[0])
        else:
            pred = int(self._model.predict(arr)[0])
            score = float(pred)

        label = "wannacry" if score >= self.threshold else "benign"
        logger.debug(
            "ML prediction: label=%s score=%.4f threshold=%.2f",
            label,
            score,
            self.threshold,
        )
        return label, score

    def is_loaded(self) -> bool:
        """Check if model is loaded."""
        return self._model is not None
