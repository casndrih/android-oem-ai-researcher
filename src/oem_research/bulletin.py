"""Offline Android Security Bulletin text correlation.

The user supplies a saved official bulletin HTML/text file; no network access occurs.
"""
from pathlib import Path
import re

CVE_RE=re.compile(r"\bCVE-\d{4}-\d{4,}\b",re.I)
SPL_RE=re.compile(r"\b20\d{2}-\d{2}-\d{2}\b")

def analyze_bulletin(path: Path, device: dict|None=None, nvd_matches=None)->dict:
    p=Path(path)
    if p.is_symlink() or not p.is_file(): raise ValueError("Bulletin must be a regular local file")
    if p.stat().st_size>20*1024*1024: raise ValueError("Bulletin exceeds 20 MiB limit")
    text=p.read_text(encoding="utf-8",errors="replace")
    ids=sorted({x.upper() for x in CVE_RE.findall(text)})
    dates=sorted(set(SPL_RE.findall(text)))
    props=(device or {}).get("properties",{})
    spl=props.get("security_patch") or props.get("ro.build.version.security_patch")
    matches=nvd_matches or []
    linked=[x for x in matches if x.get("cve_id","").upper() in ids]
    return {"source":str(p),"bulletin_cves":ids,"date_tokens":dates,
            "device_security_patch":spl,"cve_matches_in_nvd":linked,
            "status":"offline-text-correlation",
            "limitations":["CVE presence in a bulletin does not prove the device lacks the fix.",
            "A bulletin date token is not automatically a security patch level; inspect the original bulletin context.",
            "Vendor-specific bulletins and chipset advisories may add fixes not present in the Android Security Bulletin."]}
