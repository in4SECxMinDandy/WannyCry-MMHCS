"""Tests for feature extractor module."""



from core.feature_extractor import (
    NUM_FEATURES,
    _byte_histogram_bins,
    _chi_square,
    _shannon_entropy,
    extract_features,
    features_to_array,
    get_feature_names,
)


class TestShannonEntropy:
    def test_empty_data(self) -> None:
        assert _shannon_entropy(b"") == 0.0

    def test_all_same_byte(self) -> None:
        data = b"\x00" * 256
        assert _shannon_entropy(data) == 0.0

    def test_all_random_max(self) -> None:
        data = bytes(range(256)) * 100
        entropy = _shannon_entropy(data)
        assert entropy > 7.9
        assert entropy <= 8.0

    def test_typical_data(self) -> None:
        data = b"Hello World" * 100
        entropy = _shannon_entropy(data)
        assert 0.0 < entropy < 8.0


class TestChiSquare:
    def test_uniform_distribution(self) -> None:
        data = bytes(range(256)) * 10
        chi2 = _chi_square(data)
        assert chi2 == 0.0

    def test_skewed_distribution(self) -> None:
        data = b"\x00" * 256
        chi2 = _chi_square(data)
        assert chi2 > 0.0

    def test_empty_data(self) -> None:
        assert _chi_square(b"") == 0.0


class TestByteHistogramBins:
    def test_num_bins(self) -> None:
        data = bytes(range(256))
        bins = _byte_histogram_bins(data)
        assert len(bins) == 8
        for b in bins:
            assert b > 0.0

    def test_all_zero_data(self) -> None:
        data = b"\x00" * 512
        bins = _byte_histogram_bins(data)
        assert bins[0] == 1.0
        for i in range(1, 8):
            assert bins[i] == 0.0

    def test_empty_data(self) -> None:
        bins = _byte_histogram_bins(b"")
        assert bins == [0.0] * 8


class TestExtractFeatures:
    def test_valid_pe(self, tmp_pe_file) -> None:
        features = extract_features(tmp_pe_file)
        assert features is not None
        assert len(features) == NUM_FEATURES
        for i in range(1, NUM_FEATURES + 1):
            assert f"feature_{i}" in features

    def test_not_pe_file(self, tmp_text_file) -> None:
        features = extract_features(tmp_text_file)
        assert features is None

    def test_empty_file(self, tmp_empty_file) -> None:
        features = extract_features(tmp_empty_file)
        assert features is None

    def test_nonexistent_file(self, tmp_path) -> None:
        features = extract_features(tmp_path / "nonexistent.exe")
        assert features is None

    def test_wannacry_mock_has_suspicious_imports(self, tmp_pe_file_wannacry_mock) -> None:
        features = extract_features(tmp_pe_file_wannacry_mock)
        assert features is not None
        assert features["feature_1"] > 0.0
        assert features["feature_2"] > 0.0

    def test_benign_file(self, tmp_benign_file) -> None:
        features = extract_features(tmp_benign_file)
        assert features is not None
        assert features["feature_1"] > 0.0


class TestFeaturesToArray:
    def test_conversion(self) -> None:
        features = {f"feature_{i}": float(i) for i in range(1, NUM_FEATURES + 1)}
        arr = features_to_array(features)
        assert len(arr) == NUM_FEATURES
        assert arr[0] == 1.0
        assert arr[15] == 16.0


class TestGetFeatureNames:
    def test_length(self) -> None:
        names = get_feature_names()
        assert len(names) == NUM_FEATURES

    def test_non_empty(self) -> None:
        names = get_feature_names()
        for name in names:
            assert len(name) > 0
