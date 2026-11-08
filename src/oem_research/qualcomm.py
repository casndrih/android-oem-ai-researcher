"""Read-only Qualcomm QFIL/Firehose package image extraction.

Parses rawprogram XML to identify referenced image files. patch XML is metadata
only; this tool never executes Firehose commands or applies patch instructions.
"""
from pathlib import Path, PurePosixPath
import shutil, xml.etree.ElementTree as ET, zipfile

def _safe_name(value: str) -> str:
    p=PurePosixPath(value.replace("\\","/"))
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise ValueError(f"Unsafe XML image path: {value}")
    return str(p)

def parse_rawprogram(xml_text: str) -> list[dict]:
    root=ET.fromstring(xml_text)
    rows=[]
    for node in root.iter():
        if node.tag.split("}")[-1].lower()!="program": continue
        attrs={k.lower():v for k,v in node.attrib.items()}
        filename=attrs.get("filename","").strip()
        if not filename: continue
        rows.append({"filename":_safe_name(filename),"label":attrs.get("label"),
                     "start_sector":attrs.get("start_sector"),
                     "num_sectors":attrs.get("num_sectors"),
                     "physical_partition_number":attrs.get("physical_partition_number")})
    return rows

def extract_qualcomm(source: Path, destination: Path, rawprogram: Path | None=None) -> list[dict]:
    source,destination=Path(source),Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    if source.is_dir():
        if rawprogram is None:
            found=sorted(source.rglob("rawprogram*.xml"))
            if not found: raise ValueError("No rawprogram*.xml found")
            rawprogram=found[0]
        rows=parse_rawprogram(Path(rawprogram).read_text(encoding="utf-8",errors="replace"))
        results=[]
        for row in rows:
            rel=Path(row["filename"])
            match=next((p for p in source.rglob(rel.name) if p.is_file()),None)
            if match is None: continue
            target=destination/rel.name
            if target.exists(): target=destination/f"{row.get('label') or 'image'}_{rel.name}"
            shutil.copyfile(match,target)
            results.append({**row,"file":str(target),"size":target.stat().st_size})
        return results
    if not zipfile.is_zipfile(source):
        raise ValueError("Qualcomm input must be a firmware directory or ZIP package")
    with zipfile.ZipFile(source) as z:
        names=z.namelist()
        xml_member=None
        if rawprogram is not None:
            wanted=Path(rawprogram).name
            xml_member=next((n for n in names if Path(n).name==wanted),None)
            xml_text=Path(rawprogram).read_text(encoding="utf-8",errors="replace")
        else:
            xml_member=next((n for n in names if Path(n).name.lower().startswith("rawprogram") and n.lower().endswith(".xml")),None)
            if xml_member is None: raise ValueError("No rawprogram*.xml found in ZIP")
            xml_text=z.read(xml_member).decode("utf-8",errors="replace")
        rows=parse_rawprogram(xml_text); results=[]
        for row in rows:
            rel=row["filename"]
            member=next((n for n in names if n==rel or n.endswith("/"+rel)),None)
            if member is None: continue
            target=destination/Path(rel).name
            if target.exists(): target=destination/f"{row.get('label') or 'image'}_{Path(rel).name}"
            with z.open(member) as src, target.open("xb") as dst: shutil.copyfileobj(src,dst,1024*1024)
            results.append({**row,"file":str(target),"size":target.stat().st_size})
        return results
