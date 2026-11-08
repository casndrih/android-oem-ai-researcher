"""Evidence-led MTP and ADB firmware attack-surface inventory; no active probing."""
from pathlib import Path
import re
TEXT_EXT={".rc",".prop",".conf",".xml",".te",".cil",".txt",".mk",".java",".cpp",".h"}
MTP_TERMS=("MtpServer","MtpDatabase","MtpPropertyGroup","MTP_EVENT","MTP_OPERATION","MTP_RESPONSE","MtpRequestPacket","MtpPacket","media.mtp","android.hardware.usb")
ADB_TERMS=("adbd","adb_keys","adbd_auth","ro.adb.secure","service.adb.tcp.port","persist.adb.tcp.port","auth_required")
def audit_protocol_surface(root: Path)->dict:
    root=Path(root)
    if not root.is_dir(): raise ValueError("Protocol audit requires an extracted firmware directory")
    mtp=[]; adb=[]; usb=[]; scanned=0
    for p in root.rglob("*"):
        if p.is_symlink() or not p.is_file() or p.suffix.lower() not in TEXT_EXT: continue
        try:
            if p.stat().st_size>3*1024*1024: continue
            lines=p.read_text(encoding="utf-8",errors="ignore").splitlines()
        except OSError: continue
        scanned+=1
        for n,line in enumerate(lines,1):
            s=line.strip()
            if not s or s.startswith("#"): continue
            ev=f"{p.relative_to(root)}:{n}: {s[:220]}"
            if any(t.lower() in s.lower() for t in MTP_TERMS): mtp.append(ev)
            if any(t.lower() in s.lower() for t in ADB_TERMS): adb.append(ev)
            if "sys.usb.config" in s.lower() or "usb.configfs" in s.lower() or "android.hardware.usb" in s.lower(): usb.append(ev)
    findings=[]
    if mtp: findings.append({"id":"MTP-SURFACE","severity":"info","title":"MTP responder/protocol implementation references","evidence":mtp[:30],"analysis":"References identify code/configuration that may implement or expose MTP operations. They do not establish a parser flaw or remotely reachable vulnerability.","recommendation":"Trace MtpServer request dispatch, packet length/offset validation, object/property handling, storage authorization and lock-state gating in the matching source revision. Test only with a controlled USB host and authorized device."})
    if adb: findings.append({"id":"ADB-SURFACE","severity":"info","title":"ADB daemon/authentication surface references","evidence":adb[:30],"analysis":"References indicate ADB daemon, keys or transport configuration. They do not prove unauthenticated access or a known exploit.","recommendation":"Review adbd transport listeners, RSA pairing/authentication, USB function composition, shell privilege transitions and production build flags."})
    return {"scope":"static source/config inventory only; no USB enumeration, ADB connection, MTP packet injection or fuzzing","files_scanned":scanned,"mtp_evidence":mtp[:100],"adb_evidence":adb[:100],"usb_composition_evidence":usb[:100],"findings":findings,"limitations":["Protocol implementation binaries are not reverse-engineered by this module.","No live device probing or fuzzing is performed. Use an isolated, explicitly authorized lab for dynamic protocol validation."]}
