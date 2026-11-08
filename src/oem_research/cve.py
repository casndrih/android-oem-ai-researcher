"""Offline CVE correlation against user-supplied NVD JSON 2.0 exports."""
from pathlib import Path
import json,re
def _versions(cve):
    out=[]
    for node in cve.get("configurations",[]) or []:
        for n in node.get("nodes",[]) or []:
            for m in n.get("cpeMatch",[]) or []:
                if m.get("vulnerable",True): out.append(m.get("criteria",""))
    return out
def _cpe_matches(criteria, tokens):
    c=criteria.lower()
    return any(t and t.lower() in c for t in tokens)
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
        if not criteria: continue
        relevant=[x for x in criteria if _cpe_matches(x,tokens)]
        if not relevant: continue
        desc=next((d.get("value","") for d in cve.get("descriptions",[]) if d.get("lang")=="en"),"")
        metrics=cve.get("metrics",{})
        score=None; severity=None
        for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if metrics.get(key):
                cv=metrics[key][0].get("cvssData",{})
                score=cv.get("baseScore"); severity=cv.get("baseSeverity"); break
        matches.append({"cve_id":cve.get("id"),"published":cve.get("published"),"last_modified":cve.get("lastModified"),"description":desc[:1200],"cvss":score,"severity":severity,"matched_cpe":relevant[:10],"assessment":"candidate-match; verify affected version range and vendor backports"})
    return {"source":str(p),"records_examined":len(vulns),"device_tokens":tokens,"matches":matches[:500],"status":"completed","limitations":["CPE substring matching is candidate generation, not proof of applicability.","Android OEM backports and vendor-specific firmware revisions may invalidate upstream version matches.","A device security patch level does not prove that every bulletin fix is present; verify OEM release notes and shipped component versions."]}
