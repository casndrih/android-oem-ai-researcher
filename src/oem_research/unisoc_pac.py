"""Read-only parser/extractor for the documented Unisoc PAC record layout.

PAC revisions differ. This parser validates every table and payload boundary and
fails closed when a record does not match the expected 2580-byte record layout.
"""
from pathlib import Path
import struct

HEADER_MIN = 2124
HEADER_COUNT_OFF = 1076
HEADER_TABLE_OFF = 1080
RECORD_MIN = 1584
MAX_RECORDS = 10000
MAX_NAME_BYTES = 512

def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]

def _u64_pair(hi: int, lo: int) -> int:
    return (hi << 32) | lo

def _text(raw: bytes) -> str:
    return raw.decode("utf-16le", errors="ignore").split("\x00", 1)[0].strip()

def inspect_pac(path: Path) -> list[dict]:
    path = Path(path)
    size = path.stat().st_size
    with path.open("rb") as f:
        header = f.read(2584)
        if len(header) < HEADER_MIN:
            raise ValueError("PAC header is truncated")
        count = _u32(header, HEADER_COUNT_OFF)
        table = _u32(header, HEADER_TABLE_OFF)
        if count > MAX_RECORDS or table < HEADER_MIN or table >= size:
            raise ValueError("PAC table offset/count is implausible")
        records = []
        pos = table
        for index in range(count):
            f.seek(pos)
            fixed = f.read(RECORD_MIN)
            if len(fixed) < RECORD_MIN:
                raise ValueError(f"PAC record {index} is truncated")
            rec_len = _u32(fixed, 0)
            if rec_len < RECORD_MIN or rec_len > 1024 * 1024 or pos + rec_len > size:
                raise ValueError(f"PAC record {index} has invalid record length")
            name = _text(fixed[4:516]) or _text(fixed[516:1028]) or f"partition_{index}"
            file_name = _text(fixed[516:1028]) or name
            data_offset = _u64_pair(_u32(fixed, 1552), _u32(fixed, 1564))
            data_size = _u64_pair(_u32(fixed, 1540), _u32(fixed, 1556))
            if data_size and (data_offset < table or data_offset + data_size > size):
                raise ValueError(f"PAC payload bounds invalid for {name}")
            records.append({"index": index, "partition": name, "filename": file_name,
                            "offset": data_offset, "size": data_size})
            pos += rec_len
        return records

def extract_pac(path: Path, destination: Path) -> list[dict]:
    path, destination = Path(path), Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    with path.open("rb") as src:
        for rec in inspect_pac(path):
            if not rec["size"]:
                continue
            safe = Path(rec["filename"]).name
            if safe in ("", ".", ".."):
                safe = f"{rec['partition']}.img"
            target = destination / safe
            if target.exists():
                target = destination / f"{rec['index']:04d}_{safe}"
            src.seek(rec["offset"])
            remaining = rec["size"]
            with target.open("xb") as out:
                while remaining:
                    chunk = src.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError(f"Unexpected EOF extracting {safe}")
                    out.write(chunk); remaining -= len(chunk)
            results.append({"partition": rec["partition"], "file": str(target), "size": rec["size"]})
    return results
