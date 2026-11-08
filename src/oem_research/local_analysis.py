"""Local-first, read-only firmware analysis orchestration.

The input firmware stays on the user's machine. Only bounded metadata and
analysis results are written to the selected report directory.
"""
from pathlib import Path
import hashlib
import shutil

from .device_report import build_device_report
from .report import write_report
from .unisoc_pac import inspect_pac, extract_pac

PARTITION_HINTS = (
    "boot", "recovery", "system", "vendor", "userdata", "cache",
    "modem", "nv", "dsp", "u-boot", "uboot", "splash", "logo",
    "trust", "tee", "persist", "prodnv", "fixnv",
)


def _walk_regular_files(root: Path, max_files: int):
    """Yield regular files without following symlinked directories or files."""
    count = 0
    for current, dirs, names in __import__("os").walk(root, followlinks=False):
        base = Path(current)
        dirs[:] = sorted(d for d in dirs if not (base / d).is_symlink())
        for name in sorted(names):
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            count += 1
            if count > max_files:
                raise ValueError(f"File-count limit exceeded ({max_files}); narrow the firmware directory")
            yield path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inventory(root: Path, max_files: int, max_total_bytes: int) -> list[dict]:
    rows = []
    total_bytes = 0
    for path in _walk_regular_files(root, max_files):
        try:
            stat = path.stat()
            total_bytes += stat.st_size
            if total_bytes > max_total_bytes:
                raise ValueError(f"Total input-size limit exceeded ({max_total_bytes} bytes)")
            name = path.name.lower()
            hints = [hint for hint in PARTITION_HINTS if hint in name]
            rows.append({
                "path": str(path.relative_to(root)),
                "size_bytes": stat.st_size,
                "sha256": _sha256(path),
                "partition_name_hints": hints,
            })
        except OSError as exc:
            rows.append({"path": str(path.relative_to(root)), "error": str(exc)})
    return rows


def analyze_local(source: Path, out: Path, use_ai: bool = False,
                  cve_json: Path | None = None,
                  components_json: Path | None = None,
                  bulletin_file: Path | None = None,
                  max_files: int = 100000,
                  max_total_bytes: int = 20 * 1024 * 1024 * 1024) -> dict:
    """Analyze an extracted firmware directory or a single Unisoc PAC file."""
    source, out = Path(source).resolve(), Path(out).resolve()
    if not source.exists():
        raise FileNotFoundError(source)
    if max_files < 1 or max_total_bytes < 1:
        raise ValueError("max_files and max_total_bytes must be positive")

    pac_records = []
    analysis_root = source
    if source.is_file():
        if source.suffix.lower() != ".pac":
            raise ValueError("analyze-local accepts an extracted directory or a .pac file; extract .7z/.zip containers locally first")
        pac_records = inspect_pac(source)
        analysis_root = out / "pac_extracted"
        if analysis_root.exists():
            raise FileExistsError(f"Refusing to reuse existing extraction directory: {analysis_root}")
        analysis_root.mkdir(parents=True, exist_ok=False)
        extract_pac(source, analysis_root)
    elif not source.is_dir():
        raise ValueError("Input must be a regular firmware directory or .pac file")

    if source.is_dir() and (out == source or source in out.parents):
        raise ValueError("Report output must be outside the firmware source directory")
    out.mkdir(parents=True, exist_ok=True)

    files = _inventory(analysis_root, max_files, max_total_bytes)
    source_sha256 = _sha256(source) if source.is_file() else None
    device_report = build_device_report(
        analysis_root, cve_json=cve_json, use_ai=use_ai,
        components_json=components_json, bulletin_file=bulletin_file,
    )
    result = {
        "product": "DroidSec AI",
        "workflow": "local-first-read-only",
        "source": str(source),
        "source_sha256": source_sha256,
        "analysis_root": str(analysis_root),
        "inventory_total_bytes": sum(row.get("size_bytes", 0) for row in files),
        "source_firmware_modified": False,
        "device": device_report.get("device", {}),
        "pac": {
            "parsed": bool(pac_records),
            "record_count": len(pac_records),
            "records": pac_records,
            "format_note": "PAC parser is revision-dependent; verify record offsets and extracted hashes against an independent tool before treating extraction as validated.",
        } if source.is_file() else None,
        "file_count": len(files),
        "files": files,
        "security_assessment": device_report,
        "limitations": [
            "The workflow does not execute firmware binaries, connect to a phone, flash partitions, unlock bootloaders, or write to source firmware.",
            "An extracted directory is scanned as-is; raw ext4/EROFS/squashfs images are not automatically mounted or unpacked.",
            "PAC parsing is revision-dependent and must be validated against a genuine sample and an independent parser.",
            "Static ADB/MTP and SELinux findings are indicators, not proof of exploitability.",
            "CVE matches are candidates; OEM backports and exact component versions require verification.",
            "AI assessment is advisory and must not replace manual validation.",
        ],
    }
    write_report(result, out)
    return result
