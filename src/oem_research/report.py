import json
from pathlib import Path

def write_report(data: dict, out: Path):
    out=Path(out); out.mkdir(parents=True,exist_ok=True)
    (out/"report.json").write_text(json.dumps(data,indent=2),encoding="utf-8")
    (out/"report.md").write_text("# DroidSec AI report\n\n"+json.dumps(data,indent=2),encoding="utf-8")
