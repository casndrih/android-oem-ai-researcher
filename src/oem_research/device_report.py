"""Unified device-specific evidence report and optional AI interpretation."""
from pathlib import Path
from .device_fingerprint import fingerprint_firmware
from .usb_security import analyze_usb_security
from .mtp_adb_audit import audit_protocol_surface
from .selinux_audit import analyze_selinux
from .cve import correlate_nvd
def build_device_report(root: Path, cve_json: Path|None=None, use_ai: bool=False, components_json: Path|None=None)->dict:
    root=Path(root)
    device=fingerprint_firmware(root)
    report={"product":"DroidSec AI","schema_version":"1.0","device":device,
            "adb_mtp_static":analyze_usb_security(root),
            "protocol_surface":audit_protocol_surface(root),
            "selinux":analyze_selinux(root),
            "cve_correlation":correlate_nvd(root,cve_json,device,components_json)}
    if use_ai:
        from .glm import summarize
        report["ai_assessment"]=summarize(report, system_prompt=("You are an Android OEM firmware security analyst. Analyze only supplied evidence. Separate confirmed observations, plausible risks, false-positive possibilities, and unknowns. Never invent CVEs or claim exploitability from strings alone. For CVEs, explain CPE/version uncertainty and OEM backport caveats. Prioritize device-specific mitigations. Return concise JSON with executive_summary, confirmed_evidence, hypotheses, prioritized_findings, validation_plan and confidence. Do not provide exploit payloads or bypass steps."))
    return report
