"""Tests for FP reducer module."""

from pathlib import Path

from core.fp_reducer import FPReducer


class TestFPReducer:
    def test_init_empty(self) -> None:
        reducer = FPReducer()
        assert len(reducer.whitelist_hashes) == 0

    def test_init_with_data(self) -> None:
        reducer = FPReducer(
            whitelist_hashes=["abc123"],
            whitelist_paths=["/safe/path"],
        )
        assert "abc123" in reducer.whitelist_hashes
        assert "/safe/path" in reducer.whitelist_paths

    def test_is_not_whitelisted(self, tmp_pe_file) -> None:
        reducer = FPReducer()
        assert not reducer.is_whitelisted(tmp_pe_file)

    def test_is_whitelisted_path(self, tmp_path, tmp_pe_file) -> None:
        reducer = FPReducer(whitelist_paths=[str(tmp_path)])
        assert reducer.is_whitelisted(tmp_pe_file)

    def test_is_whitelisted_hash(self, tmp_path) -> None:
        file_path = tmp_path / "test.bin"
        file_path.write_bytes(b"known content")
        import hashlib
        sha = hashlib.sha256(b"known content").hexdigest()
        reducer = FPReducer(whitelist_hashes=[sha])
        assert reducer.is_whitelisted(file_path)

    def test_whitelisted_path_nonexistent(self) -> None:
        reducer = FPReducer(whitelist_paths=["/safe/path"])
        result = reducer.is_whitelisted_path(Path("/some/other/path.exe"))
        assert not result

    def test_case_insensitive_hash(self) -> None:
        reducer = FPReducer(whitelist_hashes=["ABCDEF12345"])
        assert "abcdef12345" in reducer.whitelist_hashes
