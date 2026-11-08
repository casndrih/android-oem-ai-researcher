"""Offline CVE correlation against NVD JSON 2.0 exports and component inventory."""
from pathlib import Path
import json
import re

def _normal(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())

def _versions(cve):
    out=[]
    def walk(node):
        for match in node.get("cpeMatch",[]) or []:
            if match.get("vulnerable",True): out.append(match)
        for child in node.get("nodes",[]) or []: walk(child)
    for node in cve.get("configurations",[]) or []: walk(node)
    return out

def _matches(criteria, tokens):
    parts=criteria.lower().split(":")
    normalized=[_normal(x) for x in tokens if x]
    cpe_values=[_normal(x) for x in parts[2:6] if x not in ("*","-")]
    return bool(normalized and any(t and any(t in value or value in t for value in cpe_values) for t in normalized))

def _numeric_version(value):
    if value is None or not re.fullmatch(r"\d+(?:\.\d+)*", str(value)):
        return None
    return tuple(int(x) for x in str(value).split("."))

def _compare(a,b):
    if a is None or b is None: return None
    width=max(len(a),len(b))
    aa=a+(0,)*(width-len(a)); bb=b+(0,)*(width-len(b))
    return (aa>bb)-(aa<bb)

def _range_status(version, match):
    """Return affected/not-affected/unknown using only numeric dotted versions."""
    v=_numeric_version(version)
    if v is None: return "unknown"
    lower_i=_numeric_version(match.get("versionStartIncluding"))
    lower_e=_numeric_version(match.get("versionStartExcluding"))
    upper_i=_numeric_version(match.get("versionEndIncluding"))
    upper_e=_numeric_version(match.get("versionEndExcluding"))
    if any(x is not None and _numeric_version(match.get(k)) is None for x,k in [
        (lower_i,"versionStartIncluding"),(lower_e,"versionStartExcluding"),
        (upper_i,"versionEndIncluding"),(upper_e,"versionEndExcluding")]):
        return "unknown"
    if lower_i is not None and _compare(v,lower_i)<0: return "not-affected"
    if lower_e is not None and _compare(v,lower_e)<=0: return "not-affected"
    if upper_i is not None and _compare(v,upper_i)>0: return "not-affected"
    if upper_e is not None and _compare(v,upper_e)>=0: return "not-affected"
    return "affected"

def _component_matches(component, cpe_criteria):
    cpe=component.get("cpe")
    if cpe:
        cp=[_normal(x) for x in str(cpe).split(":")[2:6]]
        target=[_normal(x) for x in cpe_criteria.split(":")[2:6]]
        return len(cp)>=2 and len(target)>=2 and cp[:2]==target[:2]
    return _matches(cpe_criteria,[component.get("name","")])

def correlate_nvd(root: Path, nvd_json: Path|None, device: dict|None=None,
                  components_json: Path|None=None)->dict:
    device=device or {}
    props=device.get("properties",{})
    tokens=[props.get(k,"") for k in ("manufacturer","brand","model","product","device","platform","hardware","soc_model")]
    tokens=[x for x in tokens if x]
    if not nvd_json:
        return {"source":"none","matches":[],"status":"not-run","note":"Supply a local NVD JSON 2.0 CVE export. No CVE is inferred from Android version alone."}
    p=Path(nvd_json); data=json.loads(p.read_text(encoding="utf-8"))
    components=[]
    if components_json:
        loaded=json.loads(Path(components_json).read_text(encoding="utf-8"))
        components=loaded.get("components",loaded if isinstance(loaded,list) else [])
        if not isinstance(components,list): raise ValueError("Component inventory must be a JSON list or an object with a components list")
    vulns=data.get("vulnerabilities",[]); matches=[]
    for item in vulns:
        cve=item.get("cve",item); criteria=_versions(cve)
        relevant=[x for x in criteria if _matches(x.get("criteria",""),tokens) or
                  any(_component_matches(comp,x.get("criteria","")) for comp in components)]
        if not relevant: continue
        desc=next((d.get("value","") for d in cve.get("descriptions",[]) if d.get("lang")=="en"),"")
        metrics=cve.get("metrics",{}); score=None; severity=None
        for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if metrics.get(key):
                cv=metrics[key][0].get("cvssData",{}); score=cv.get("baseScore"); severity=cv.get("baseSeverity"); break
        component_checks=[]
        for comp in components:
            for rule in relevant:
                if _component_matches(comp,rule.get("criteria","")):
                    component_checks.append({"component":comp.get("name"),"version":comp.get("version"),
                        "criteria":rule.get("criteria"),"version_assessment":_range_status(comp.get("version"),rule)})
        statuses={x["version_assessment"] for x in component_checks}
        assessment=("version-range-candidate" if "affected" in statuses else
                    "version-outside-range" if component_checks and statuses=={"not-affected"} else
                    "version-unknown" if component_checks else "candidate-match; no component version supplied")
        matches.append({"cve_id":cve.get("id"),"published":cve.get("published"),"last_modified":cve.get("lastModified"),
            "description":desc[:1200],"cvss":score,"severity":severity,
            "matched_cpe":[x.get("criteria") for x in relevant[:10]],
            "version_constraints":[{k:x.get(k) for k in ("versionStartIncluding","versionStartExcluding","versionEndIncluding","versionEndExcluding")} for x in relevant[:10]],
            "component_checks":component_checks[:50],"assessment":assessment})
    return {"source":str(p),"records_examined":len(vulns),"device_tokens":tokens,
        "component_inventory_source":str(components_json) if components_json else None,
        "component_count":len(components),"matches":matches[:500],"status":"completed",
        "limitations":["CPE matching is candidate generation, not proof of applicability.",
        "Version comparison is performed only for numeric dotted versions; Android build IDs and vendor version strings remain unknown.",
        "OEM backports and firmware-specific patches may invalidate upstream version-range assessments.",
        "A device security patch level does not prove every bulletin fix is present; verify OEM release notes and shipped component versions."]}
