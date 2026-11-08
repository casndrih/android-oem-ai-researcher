import json
from pathlib import Path
from oem_research.selinux_audit import analyze_selinux
from oem_research.mtp_adb_audit import audit_protocol_surface
from oem_research.cve import correlate_nvd
from oem_research.device_report import build_device_report

def test_selinux_source_findings(tmp_path: Path):
    p=tmp_path/"vendor"/"sepolicy"
    p.mkdir(parents=True)
    (p/"vendor.te").write_text("permissive vendor_debug;\nallow adbd system_file:file *;\nallow mtp media_rw_data_file:dir { read write search };\n")
    result=analyze_selinux(tmp_path)
    ids={x["id"] for x in result["findings"]}
    assert {"SE-001","SE-002","SE-003","SE-004"} <= ids

def test_protocol_surface_evidence(tmp_path: Path):
    p=tmp_path/"system"/"etc"/"init"
    p.mkdir(parents=True)
    (p/"usb.rc").write_text("service adbd /system/bin/adbd\nsetprop sys.usb.config mtp,adb\n")
    result=audit_protocol_surface(tmp_path)
    assert result["adb_evidence"]
    assert result["usb_composition_evidence"]

def test_nvd_cpe_candidate_matching(tmp_path: Path):
    db={"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","published":"2024-01-01","descriptions":[{"lang":"en","value":"Test issue"}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":True,"criteria":"cpe:2.3:o:samsung:sm-a556e_firmware:*:*:*:*:*:*:*:*"}]}]}]}}]}
    f=tmp_path/"nvd.json"; f.write_text(json.dumps(db))
    device={"properties":{"manufacturer":"Samsung","model":"SM-A556E"}}
    result=correlate_nvd(tmp_path,f,device)
    assert result["matches"][0]["cve_id"]=="CVE-2024-0001"
    assert "candidate-match" in result["matches"][0]["assessment"]

def test_unified_device_report(tmp_path: Path):
    (tmp_path/"system").mkdir()
    (tmp_path/"system"/"build.prop").write_text("ro.product.manufacturer=Samsung\nro.product.model=SM-A556E\n")
    result=build_device_report(tmp_path)
    assert result["device"]["properties"]["model"]=="SM-A556E"
    assert "selinux" in result and "protocol_surface" in result and "cve_correlation" in result
