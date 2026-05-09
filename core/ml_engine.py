"""Machine learning engine for ransomware detection via Random Forest."""

from pathlib import Path

import joblib
import numpy as np

from core.feature_extractor import features_to_array
from core.logger_setup import get_logger

logger = get_logger(__name__)


class MLEngine:
    """Random Forest-based ransomware detection engine (WannaCry & BlackCat)."""

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

        Supports both legacy single-object pickles and new dict pickles
        that include label_classes for proper decoding.

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
            data = joblib.load(self.model_path)
            if isinstance(data, dict) and "model" in data:
                model = data["model"]
                self._label_classes = data.get("label_classes")
            else:
                model = data
                self._label_classes = None
            logger.info("Model loaded from %s", self.model_path)
            return model
        except Exception as e:
            logger.error("Failed to load model from %s: %s", self.model_path, e)
            raise

    def predict(self, features: dict[str, float]) -> tuple[str, float]:
        """Predict whether features indicate ransomware.

        Args:
            features: Dictionary of feature_1 through feature_16 from feature_extractor.

        Returns:
            Tuple of (label, score) where label is "wannacry", "blackcat", or "benign".

        Raises:
            RuntimeError: If model is not loaded.
        """
        if self._model is None:
            raise RuntimeError("Model not loaded")

        arr = np.array([features_to_array(features)], dtype=np.float32)

        if hasattr(self._model, "predict_proba"):
            proba = self._model.predict_proba(arr)[0]
            classes = self._model.classes_

            # Build label map: class index -> human-readable label
            label_map: dict[int | str, str] = {}
            if self._label_classes is not None:
                for i, cls in enumerate(classes):
                    idx = int(cls)
                    if 0 <= idx < len(self._label_classes):
                        label_map[cls] = str(self._label_classes[idx]).lower()
            else:
                # Legacy fallback: infer from number of classes
                # 2-class [0,1]: 0=benign, 1=wannacry (original binary model)
                # 3-class [0,1,2]: 0=benign, 1=blackcat, 2=wannacry (LabelEncoder alphabetical)
                numeric_classes = []
                for cls in classes:
                    try:
                        numeric_classes.append(int(cls))
                    except (ValueError, TypeError):
                        numeric_classes = None
                        break
                if numeric_classes is not None and len(numeric_classes) == 3 and set(numeric_classes) == {0, 1, 2}:
                    legacy_map = {0: "benign", 1: "blackcat", 2: "wannacry"}
                else:
                    legacy_map = {0: "benign", 1: "wannacry"}
                for cls in classes:
                    try:
                        label_map[cls] = legacy_map.get(int(cls), str(cls).lower())
                    except (ValueError, TypeError):
                        label_map[cls] = str(cls).lower()

            malware_classes = {"wannacry", "blackcat", "malicious"}
            best_label = "benign"
            best_score = 0.0
            for i, cls in enumerate(classes):
                cls_str = label_map.get(cls, str(cls).lower())
                if cls_str in malware_classes:
                    if float(proba[i]) > best_score:
                        best_score = float(proba[i])
                        best_label = cls_str if cls_str in ("wannacry", "blackcat") else "wannacry"
            score = best_score
        else:
            pred = int(self._model.predict(arr)[0])
            score = float(pred)
            best_label = "wannacry" if pred else "benign"

        label = best_label if score >= self.threshold else "benign"
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
