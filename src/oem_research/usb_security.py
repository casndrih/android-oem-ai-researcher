"""Static, read-only ADB and MTP configuration review of extracted Android firmware."""
from pathlib import Path
import re

TEXT_LIMIT = 2 * 1024 * 1024
TEXT_SUFFIXES = {".prop", ".rc", ".te", ".cil", ".xml", ".conf", ".mk", ".txt"}

def _finding(rule, title, severity, evidence, explanation, recommendation):
    return {"id": rule, "title": title, "severity": severity, "evidence": evidence[:8],
            "analysis": explanation, "recommendation": recommendation,
            "status": "needs-manual-validation"}

def analyze_usb_security(root: Path) -> dict:
    root = Path(root)
    if not root.is_dir():
        raise ValueError("Security analysis input must be an extracted firmware directory")
    findings, scanned = [], 0
    adb_enabled, adb_tcp, adb_auth_disabled, mtp_refs, usb_props = [], [], [], [], []
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            if path.stat().st_size > TEXT_LIMIT:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        scanned += 1
        rel = str(path.relative_to(root))
        for n, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            ev = f"{rel}:{n}: {line.strip()[:240]}"
            if re.search(r"persist\.service\.adb\.enable\s*=\s*1|service\.adb\.root\s*=\s*1", low):
                adb_enabled.append(ev)
            if re.search(r"service\.adb\.tcp\.port\s*(?:=\s*|\s+)(?!-1\b)\d+", low) or re.search(r"setprop\s+service\.adb\.tcp\.port\s+\d+", low) or "tcp:5555" in low:
                adb_tcp.append(ev)
            if re.search(r"ro\.adbd\.secure\s*=\s*0|ro\.debuggable\s*=\s*1", low) or re.search(r"setprop\s+ro\.adbd\.secure\s+0", low):
                adb_auth_disabled.append(ev)
            if "mtp" in low or "media_transfer" in low:
                mtp_refs.append(ev)
            if "sys.usb.config" in low or "persist.sys.usb.config" in low or "vendor.usb.config" in low:
                usb_props.append(ev)
    if adb_tcp:
        findings.append(_finding("ADB-001", "ADB TCP/IP listener configured", "high", adb_tcp,
            "Firmware text contains a non-disabled ADB TCP/IP port configuration. This is evidence of a potential network debugging exposure, not proof that the port is reachable at runtime.",
            "Disable network ADB in production builds; require explicit authenticated pairing and restrict debugging to trusted networks."))
    if adb_auth_disabled:
        findings.append(_finding("ADB-002", "ADB authentication/debuggable hardening concern", "high", adb_auth_disabled,
            "Properties indicate adbd authentication may be disabled or the build may be debuggable. Build variants and property overrides must be checked before confirming exposure.",
            "Use a production user build, enforce adbd authentication, remove debug properties and verify effective properties on an authorized test device."))
    if adb_enabled:
        findings.append(_finding("ADB-003", "ADB enabled by firmware property", "medium", adb_enabled,
            "A property enables ADB. ADB being enabled is not itself a vulnerability; risk depends on authentication, transport, build type and physical access controls.",
            "Ensure USB debugging is opt-in, authenticated, and disabled by default on production devices."))
    if mtp_refs:
        findings.append(_finding("MTP-001", "MTP/USB media-transfer configuration detected", "info", mtp_refs + usb_props,
            "MTP-related service or USB composition references were found. Static strings alone cannot establish an exploitable MTP flaw.",
            "Review MTP service permissions, USB function exposure, lock-state policy, file-system access boundaries and vendor patches. Validate with an authorized isolated device."))
    if not findings:
        findings.append(_finding("USB-000", "No obvious ADB/MTP indicators found", "info", [],
            "The scanned text files did not contain the static indicators covered by these rules. This is not proof that ADB or MTP is absent or secure.",
            "Inspect additional init, property, SELinux and framework artifacts; validate runtime behavior on an authorized test device."))
    return {"scope": "static firmware text only; no device connection or exploit execution",
            "files_scanned": scanned, "findings": findings,
            "indicators": {"adb_enabled": adb_enabled[:20], "adb_tcp": adb_tcp[:20],
                           "adb_auth_or_debuggable": adb_auth_disabled[:20],
                           "mtp_references": mtp_refs[:20], "usb_properties": usb_props[:20]},
            "limitations": ["This is a heuristic triage, not a CVE determination or proof of exploitability.",
                            "It does not fuzz MTP, send ADB commands, bypass pairing, or test a live device.",
                            "AI output is advisory; validate findings against source code, CVEs and an authorized lab device."]}
