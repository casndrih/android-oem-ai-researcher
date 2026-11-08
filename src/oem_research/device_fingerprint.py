"""Evidence-based Android device/OEM fingerprinting from extracted firmware trees."""
from pathlib import Path
import re

PROP_FILES = {"build.prop", "default.prop", "prop.default", "vendor.prop", "product.prop", "odm.prop"}
KEYS = {
    "ro.product.manufacturer": "manufacturer", "ro.product.brand": "brand",
    "ro.product.model": "model", "ro.product.name": "product",
    "ro.product.device": "device", "ro.build.fingerprint": "build_fingerprint",
    "ro.build.version.release": "android_version", "ro.build.version.sdk": "sdk",
    "ro.board.platform": "platform", "ro.hardware": "hardware",
    "ro.boot.hardware": "boot_hardware", "ro.soc.model": "soc_model",
    "ro.bootloader": "bootloader",
}

def fingerprint_firmware(root: Path) -> dict:
    root = Path(root)
    if not root.is_dir():
        raise ValueError("Fingerprint input must be an extracted firmware directory")
    values, sources = {}, {}
    scanned = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.name.lower() not in PROP_FILES:
            continue
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        scanned += 1
        for line in content.splitlines():
            match = re.match(r"\s*([\w.]+)\s*=\s*(.*?)\s*$", line)
            if match and match.group(1) in KEYS and match.group(2):
                key, value = KEYS[match.group(1)], match.group(2)
                if key not in values or key in ("manufacturer", "model", "device"):
                    values.setdefault(key, value)
                    sources.setdefault(key, str(path))
    # Infer only a vendor family from explicit identifiers; never guess an exact model.
    haystack = " ".join(values.values()).lower()
    vendor = values.get("manufacturer") or values.get("brand")
    if not vendor:
        for token, name in (("samsung", "Samsung"), ("huawei", "Huawei"), ("honor", "Honor"),
                            ("zte", "ZTE"), ("mediatek", "MediaTek platform"),
                            ("unisoc", "Unisoc platform"), ("qualcomm", "Qualcomm platform")):
            if token in haystack:
                vendor = name
                break
    return {"identified": bool(values), "vendor_or_brand": vendor,
            "confidence": "high" if values.get("model") and values.get("build_fingerprint") else
                          "medium" if values else "insufficient-evidence",
            "properties": values, "evidence_files": sources, "property_files_scanned": scanned,
            "limitations": ["Fingerprinting is based on extracted text properties; spoofed or missing properties can misidentify a device.",
                            "Exact model identification requires corroborating OEM metadata or a trusted device manifest."]}
