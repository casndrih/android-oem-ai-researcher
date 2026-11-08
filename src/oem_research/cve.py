"""Offline CVE correlation against user-supplied NVD JSON 2.0 exports."""
from pathlib import Path
import json
import re

def _normal(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())

def _versions(cve):
    out=[]
    def walk(node):
        for match in node.get("cpeMatch",[]) or []:
            if match.get("vulnerable",True):
                out.append(match)
        for child in node.get("nodes",[]) or []:
            walk(child)
    for node in cve.get("configurations",[]) or []:
        walk(node)
    return out

def _matches(criteria, tokens):
    parts=criteria.lower().split(":")
    normalized=[_normal(x) for x in tokens if x]
    # Product/vendor CPE components only; do not match arbitrary descriptions.
    cpe_values=[_normal(x) for x in parts[2:6] if x not in ("*","-")]
    return bool(normalized and any(t and any(t in value or value in t for value in cpe_values) for t in normalized))

def correlate_nvd(root: Path, nvd_json: Path|None, device: dict|None=None)->dict:
    device=device or {}
    props=device.get("properties",{})
    tokens=[props.get(k,"") for k in ("manufacturer","brand","model","product","device","platform","hardware","soc_model")]
    tokens=[x for x in tokens if x]
    if not nvd_json:
        return {"source":"none","matches":[],"status":"not-run","note":"Supply a local NVD JSON 2.0 CVE export. No CVE is inferred from Android version alone."}
    p=Path(nvd_json)
    data=json.loads(p.read_text(encoding="utf-8"))
    vulns=data.get("vulnerabilities",[])
    matches=[]
    for item in vulns:
        cve=item.get("cve",item)
        criteria=_versions(cve)
        relevant=[x for x in criteria if _matches(x.get("criteria",""),tokens)]
        if not relevant: continue
        desc=next((d.get("value","") for d in cve.get("descriptions",[]) if d.get("lang")=="en"),"")
        metrics=cve.get("metrics",{})
        score=None; severity=None
        for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if metrics.get(key):
                cv=metrics[key][0].get("cvssData",{})
                score=cv.get("baseScore"); severity=cv.get("baseSeverity"); break
        matches.append({"cve_id":cve.get("id"),"published":cve.get("published"),"last_modified":cve.get("lastModified"),"description":desc[:1200],"cvss":score,"severity":severity,"matched_cpe":[x.get("criteria") for x in relevant[:10]],"version_constraints":[{k:x.get(k) for k in ("versionStartIncluding","versionStartExcluding","versionEndIncluding","versionEndExcluding")} for x in relevant[:10]],"assessment":"candidate-match; verify affected version range and vendor backports"})
    return {"source":str(p),"records_examined":len(vulns),"device_tokens":tokens,"matches":matches[:500],"status":"completed","limitations":["CPE vendor/product matching is candidate generation, not proof of applicability.","CPE version bounds are reported but are not evaluated against a normalized OEM firmware component inventory yet.","Android OEM backports and vendor-specific firmware revisions may invalidate upstream version matches.","A device security patch level does not prove that every bulletin fix is present; verify OEM release notes and shipped component versions."]}
