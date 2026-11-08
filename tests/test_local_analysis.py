import json
from pathlib import Path
import pytest

from oem_research.local_analysis import analyze_local


def test_local_directory_analysis_writes_report_and_hashes(tmp_path, monkeypatch):
    from oem_research import local_analysis

    firmware = tmp_path / "firmware"
    firmware.mkdir()
    (firmware / "build.prop").write_text(
        "ro.product.manufacturer=Polytron\nro.product.model=R2406\n"
        "ro.build.version.release=4.4.2\n", encoding="utf-8"
    )
    (firmware / "init.rc").write_text("service adbd /sbin/adbd\n", encoding="utf-8")
    monkeypatch.setattr(local_analysis, "build_device_report", lambda *a, **k: {
        "device": {"properties": {"model": "R2406"}}, "adb_mtp_static": {}
    })
    out = tmp_path / "reports"
    result = analyze_local(firmware, out)
    assert result["file_count"] == 2
    assert result["source_firmware_modified"] is False
    assert result["device"]["properties"]["model"] == "R2406"
    assert len(result["files"][0]["sha256"]) == 64
    saved = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert saved["workflow"] == "local-first-read-only"


def test_local_analysis_rejects_non_pac_file(tmp_path):
    source = tmp_path / "firmware.bin"
    source.write_bytes(b"not a PAC")
    with pytest.raises(ValueError, match=r"\.pac"):
        analyze_local(source, tmp_path / "reports")


def test_local_analysis_file_limit(tmp_path, monkeypatch):
    from oem_research import local_analysis
    firmware = tmp_path / "firmware"
    firmware.mkdir()
    (firmware / "a").write_text("a")
    (firmware / "b").write_text("b")
    monkeypatch.setattr(local_analysis, "build_device_report", lambda *a, **k: {"device": {}})
    with pytest.raises(ValueError, match="File-count limit"):
        analyze_local(firmware, tmp_path / "reports", max_files=1)


def test_local_analysis_skips_symlinked_files(tmp_path, monkeypatch):
    from oem_research import local_analysis
    firmware = tmp_path / "firmware"
    firmware.mkdir()
    (firmware / "safe.txt").write_text("safe")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    try:
        (firmware / "linked.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    monkeypatch.setattr(local_analysis, "build_device_report", lambda *a, **k: {"device": {}})
    result = analyze_local(firmware, tmp_path / "reports")
    assert [row["path"] for row in result["files"]] == ["safe.txt"]


def test_local_analysis_orchestrates_pac_extraction(tmp_path, monkeypatch):
    from oem_research import local_analysis

    pac = tmp_path / "sample.pac"
    pac.write_bytes(b"synthetic PAC placeholder")
    def fake_inspect(path):
        return [{"partition": "system", "filename": "system.img", "offset": 0, "size": 4}]
    def fake_extract(path, destination):
        (destination / "system.img").write_bytes(b"TEST")
        return [{"partition": "system", "file": str(destination / "system.img"), "size": 4}]
    monkeypatch.setattr(local_analysis, "inspect_pac", fake_inspect)
    monkeypatch.setattr(local_analysis, "extract_pac", fake_extract)
    monkeypatch.setattr(local_analysis, "build_device_report", lambda *a, **k: {"device": {}})
    result = analyze_local(pac, tmp_path / "reports")
    assert result["pac"]["parsed"] is True
    assert result["pac"]["record_count"] == 1
    assert (tmp_path / "reports" / "pac_extracted" / "system.img").read_bytes() == b"TEST"


def test_local_analysis_enforces_total_byte_limit(tmp_path, monkeypatch):
    from oem_research import local_analysis
    firmware = tmp_path / "firmware"
    firmware.mkdir()
    (firmware / "large.bin").write_bytes(b"123456")
    monkeypatch.setattr(local_analysis, "build_device_report", lambda *a, **k: {"device": {}})
    with pytest.raises(ValueError, match="Total input-size limit"):
        analyze_local(firmware, tmp_path / "reports", max_total_bytes=5)
