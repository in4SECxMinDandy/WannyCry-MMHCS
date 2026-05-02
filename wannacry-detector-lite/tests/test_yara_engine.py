"""Tests for YARA engine module."""

import pytest

from core.yara_engine import YaraEngine, YaraMatch


class TestYaraEngine:
    def test_compile_rules(self, tmp_wannacry_yara) -> None:
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        assert engine.is_compiled() is True
        assert engine.get_rule_count() > 0

    def test_rules_not_found(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            YaraEngine(rules_path=tmp_path / "nonexistent.yar")

    def test_lazy_compile(self, tmp_wannacry_yara) -> None:
        engine = YaraEngine(rules_path=tmp_wannacry_yara, compile_on_load=False)
        assert engine.is_compiled() is False

    def test_scan_bytes_mutex(self, tmp_wannacry_yara) -> None:
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        prefix = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        data = prefix + b"MsWinZonesCacheCounterMutexA" + b"\x00" * 500
        matches = engine.scan_bytes(data)
        assert len(matches) > 0
        rule_names = [m.rule_name for m in matches]
        assert "WannaCry_Mutex" in rule_names

    def test_scan_bytes_wannacry_strings(self, tmp_wannacry_yara) -> None:
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        prefix = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        data = prefix + b"WANACRY!....Wanna Decryptor" + b"\x00" * 500
        matches = engine.scan_bytes(data)
        rule_names = [m.rule_name for m in matches]
        assert "WannaCry_Strings" in rule_names

    def test_scan_bytes_killswitch(self, tmp_wannacry_yara) -> None:
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        prefix = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        domain = b"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
        data = prefix + domain + b"\x00" * 500
        matches = engine.scan_bytes(data)
        rule_names = [m.rule_name for m in matches]
        assert "WannaCry_Killswitch" in rule_names

    def test_scan_benign_data_no_match(self, tmp_wannacry_yara) -> None:
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        data = b"This is a normal program" * 100
        matches = engine.scan_bytes(data)
        assert len(matches) == 0

    def test_scan_file_wannacry_mock(self, tmp_wannacry_yara, tmp_pe_file_wannacry_mock) -> None:
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        matches = engine.scan_file(tmp_pe_file_wannacry_mock)
        assert len(matches) > 0

    def test_scan_file_benign(self, tmp_wannacry_yara, tmp_benign_file) -> None:
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        matches = engine.scan_file(tmp_benign_file)
        assert len(matches) == 0

    def test_scan_file_nonexistent(self, tmp_wannacry_yara, tmp_path) -> None:
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        matches = engine.scan_file(tmp_path / "nonexistent.exe")
        assert len(matches) == 0

    def test_yara_match_dataclass(self) -> None:
        match = YaraMatch(
            rule_name="TestRule",
            tags=["wannacry"],
            meta={"author": "test"},
            strings_matched=["$s1"],
        )
        assert match.rule_name == "TestRule"
        assert "wannacry" in match.tags
        assert match.meta["author"] == "test"

    def test_get_rule_count(self, tmp_wannacry_yara) -> None:
        engine = YaraEngine(rules_path=tmp_wannacry_yara)
        assert engine.get_rule_count() >= 4
