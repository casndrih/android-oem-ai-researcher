"""Read-only GPT partition table parser for raw disk images."""
from pathlib import Path
import struct
import uuid
import zlib

def inspect_gpt(path: Path, sector_size: int = 512) -> dict:
    path = Path(path)
    if sector_size not in (512, 4096):
        raise ValueError("Sector size must be 512 or 4096")
    with path.open("rb") as f:
        f.seek(sector_size)
        h = f.read(sector_size)
        if len(h) < 92 or h[:8] != b"EFI PART":
            raise ValueError("GPT header signature not found at LBA 1")
        values = struct.unpack_from("<IIIIQQQQ16sQIII", h, 8)
        revision, header_size, header_crc, reserved, current, backup, first, last, disk_guid, entries_lba, count, entry_size, entries_crc = values
        if header_size < 92 or header_size > sector_size:
            raise ValueError("Invalid GPT header size")
        header = bytearray(h[:header_size])
        header[16:20] = b"\0\0\0\0"
        if zlib.crc32(header) & 0xffffffff != header_crc:
            raise ValueError("GPT header CRC mismatch")
        if entry_size < 128 or entry_size > 4096 or count > 16384:
            raise ValueError("Invalid GPT entry geometry")
        if entries_lba * sector_size + count * entry_size > path.stat().st_size:
            raise ValueError("GPT entries extend beyond image")
        f.seek(entries_lba * sector_size)
        raw = f.read(count * entry_size)
        if len(raw) != count * entry_size:
            raise ValueError("Truncated GPT entries")
        if zlib.crc32(raw) & 0xffffffff != entries_crc:
            raise ValueError("GPT partition-entry array CRC mismatch")
    rows = []
    for i in range(count):
        e = raw[i * entry_size:(i + 1) * entry_size]
        type_guid = e[:16]
        if type_guid == b"\0" * 16:
            continue
        unique = e[16:32]
        first_lba, last_lba, attrs = struct.unpack_from("<QQQ", e, 32)
        name = e[56:min(entry_size, 128)].decode("utf-16le", errors="ignore").split("\0", 1)[0]
        if first_lba > last_lba or last_lba >= path.stat().st_size // sector_size:
            raise ValueError(f"Invalid GPT bounds for partition {name}")
        rows.append({
            "index": i + 1, "name": name,
            "type_guid": str(uuid.UUID(bytes_le=type_guid)),
            "guid": str(uuid.UUID(bytes_le=unique)),
            "first_lba": first_lba, "last_lba": last_lba,
            "offset": first_lba * sector_size,
            "size": (last_lba - first_lba + 1) * sector_size,
            "attributes": attrs
        })
    return {
        "sector_size": sector_size, "disk_guid": str(uuid.UUID(bytes_le=disk_guid)),
        "first_usable_lba": first, "last_usable_lba": last, "partitions": rows
    }

def extract_gpt_partitions(path: Path, destination: Path, sector_size: int = 512) -> list[dict]:
    path, destination = Path(path), Path(destination)
    table = inspect_gpt(path, sector_size)
    destination.mkdir(parents=True, exist_ok=True)
    output = []
    with path.open("rb") as src:
        for part in table["partitions"]:
            name = "".join(c if c.isalnum() or c in "-_." else "_" for c in part["name"]) or f"partition_{part['index']}"
            target = destination / f"{part['index']:02d}_{name}.img"
            src.seek(part["offset"])
            remaining = part["size"]
            with target.open("xb") as dst:
                while remaining:
                    chunk = src.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Unexpected EOF while extracting GPT partition")
                    dst.write(chunk)
                    remaining -= len(chunk)
            output.append({"partition": part["name"], "file": str(target), "size": part["size"]})
    return output
