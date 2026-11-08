from pathlib import Path
from oem_research.device_fingerprint import fingerprint_firmware
from oem_research.usb_security import analyze_usb_security

def test_device_fingerprint(tmp_path: Path):
    (tmp_path / "system").mkdir()
    (tmp_path / "system" / "build.prop").write_text(
        "ro.product.manufacturer=Samsung\nro.product.model=SM-A556E\n"
        "ro.product.device=a55x\nro.build.fingerprint=samsung/a55x/a55x:14/ABC/1:user/release-keys\n"
    )
    result = fingerprint_firmware(tmp_path)
    assert result["properties"]["model"] == "SM-A556E"
    assert result["vendor_or_brand"] == "Samsung"
    assert result["confidence"] == "high"

def test_usb_static_indicators(tmp_path: Path):
    (tmp_path / "vendor" / "etc" / "init").mkdir(parents=True)
    (tmp_path / "vendor" / "etc" / "init" / "usb.rc").write_text(
        "setprop service.adb.tcp.port 5555\n"
        "setprop ro.adbd.secure 0\n"
        "on property:sys.usb.config=mtp,adb\n"
    )
    result = analyze_usb_security(tmp_path)
    ids = {x["id"] for x in result["findings"]}
    assert "ADB-001" in ids
    assert "ADB-002" in ids
    assert "MTP-001" in ids

def test_usb_no_indicators_is_not_secure_claim(tmp_path: Path):
    result = analyze_usb_security(tmp_path)
    assert result["findings"][0]["id"] == "USB-000"
    assert "not proof" in result["findings"][0]["analysis"]
