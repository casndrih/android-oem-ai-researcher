"""Read-only Android SELinux policy source audit with optional SETools integration."""
from pathlib import Path
import re
TEXT_SUFFIXES={".te",".cil",".fc",".file_contexts",".seapp",".prop",".rc"}
def analyze_selinux(root: Path) -> dict:
    root=Path(root)
    if not root.is_dir(): raise ValueError("SELinux analysis requires an extracted firmware directory")
    findings=[]; scanned=0; allow_count=0; permissive=[]; broad=[]; usb=[]; adb=[]
    for p in root.rglob("*"):
        if not p.is_file() or (p.suffix.lower() not in TEXT_SUFFIXES and p.name not in {"sepolicy","plat_sepolicy.cil","vendor_sepolicy.cil"}): continue
        try:
            if p.stat().st_size>8*1024*1024: continue
            data=p.read_text(encoding="utf-8",errors="ignore")
        except (OSError,UnicodeError): continue
        scanned+=1
        for n,line in enumerate(data.splitlines(),1):
            s=line.strip()
            if not s or s.startswith("#"): continue
            ev=f"{p.relative_to(root)}:{n}: {s[:220]}"
            if re.search(r"^\s*permissive\s+[\w.]+\s*;",s):
                permissive.append(ev)
            if re.search(r"^\s*allow\s+",s):
                allow_count+=1
                if re.search(r"\*\s*:\s*\*\s*\*|\{\s*[^}]*\*[^}]*\s*\}",s):
                    broad.append(ev)
                if re.search(r"(?:mtp|media_rw|usb|adbd)",s,re.I): usb.append(ev)
                if re.search(r"adbd|shell",s,re.I): adb.append(ev)
    if permissive:
        findings.append({"id":"SE-001","severity":"high","title":"Permissive SELinux domains declared","evidence":permissive[:20],"analysis":"Source policy explicitly marks one or more domains permissive. Confirm the compiled policy and build variant; source declarations may not be active in the shipped image.","recommendation":"Remove permissive declarations from production policy and verify enforcing mode and domain transitions."})
    if broad:
        findings.append({"id":"SE-002","severity":"high","title":"Potentially broad SELinux allow rules","evidence":broad[:20],"analysis":"Wildcard-like allow statements were found. The parser flags syntax for manual review; it does not expand attributes or prove effective access.","recommendation":"Use SETools sesearch/apol against the compiled policy, expand attributes, and narrow source/target/class/permissions."})
    if usb:
        findings.append({"id":"SE-003","severity":"medium","title":"USB/MTP-related SELinux rules","evidence":usb[:20],"analysis":"USB, MTP or media-related SELinux access rules were found. This is attack-surface context, not a vulnerability by itself.","recommendation":"Review effective rules for adbd, mtp, media_rw and related domains; verify file labels and least privilege."})
    if adb:
        findings.append({"id":"SE-004","severity":"medium","title":"ADB/shell SELinux policy references","evidence":adb[:20],"analysis":"Rules involving adbd or shell domains were found. Their effective privilege depends on attributes, macros and compiled policy expansion.","recommendation":"Inspect domain transitions and effective permissions using SETools on the compiled policy."})
    return {"scope":"SELinux source text triage; compiled binary policy requires SETools/libsepol","files_scanned":scanned,"allow_rules_seen":allow_count,"findings":findings,"limitations":["Does not compile or modify policy.","Text parser cannot expand m4 macros, CIL attributes, neverallow constraints or policy conditionals.","For authoritative results, run seinfo/sesearch/apol or SETools against the exact compiled sepolicy from this firmware."]}
