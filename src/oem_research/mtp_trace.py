"""Safe decoder for concatenated MTP containers captured from an authorized trace.

This module parses bytes only. It never opens USB devices or sends protocol traffic.
"""
from __future__ import annotations
from pathlib import Path
import struct

MTP_HEADER = struct.Struct("<IHHI")
MTP_TYPES = {1: "command", 2: "data", 3: "response", 4: "event"}
MAX_CONTAINER = 16 * 1024 * 1024
MAX_CONTAINERS = 100000

def decode_mtp_bytes(data: bytes, max_container: int = MAX_CONTAINER) -> dict:
    if max_container < MTP_HEADER.size:
        raise ValueError("max_container is smaller than an MTP header")
    records, issues, offset = [], [], 0
    while offset < len(data):
        if len(records) >= MAX_CONTAINERS:
            issues.append({"offset": offset, "issue": "container-count-limit"})
            break
        remaining = len(data) - offset
        if remaining < MTP_HEADER.size:
            issues.append({"offset": offset, "issue": "truncated-header", "remaining": remaining})
            break
        length, kind, code, txid = MTP_HEADER.unpack_from(data, offset)
        if length < MTP_HEADER.size:
            issues.append({"offset": offset, "issue": "invalid-container-length", "length": length})
            break
        if length > max_container:
            issues.append({"offset": offset, "issue": "container-size-limit", "length": length})
            break
        if length > remaining:
            issues.append({"offset": offset, "issue": "truncated-container", "declared": length, "available": remaining})
            break
        records.append({"offset": offset, "length": length, "type_code": kind,
                        "type": MTP_TYPES.get(kind, "unknown"), "code": f"0x{code:04x}",
                        "transaction_id": txid, "payload_length": length - MTP_HEADER.size})
        offset += length
    tx_seen = {}
    for item in records:
        if item["type"] in ("command", "data", "response"):
            tx_seen.setdefault(item["transaction_id"], []).append(item["type"])
    for txid, phases in tx_seen.items():
        if "data" in phases and "command" not in phases:
            issues.append({"issue": "data-without-command", "transaction_id": txid})
        if "response" in phases and "command" not in phases:
            issues.append({"issue": "response-without-command", "transaction_id": txid})
    return {"protocol": "MTP", "input_bytes": len(data), "containers": records,
            "issues": issues, "summary": {"container_count": len(records),
            "event_count": sum(x["type"] == "event" for x in records),
            "unknown_type_count": sum(x["type"] == "unknown" for x in records),
            "malformed": bool(issues)},
            "limitations": ["Requires a raw concatenated MTP container stream; USBPcap/pcapng framing is not decoded.",
                            "Container decoding is structural, not a complete semantic validation of MTP operations."]}

def decode_mtp_file(path: Path, max_bytes: int = 256 * 1024 * 1024) -> dict:
    path = Path(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"Input exceeds {max_bytes} byte limit")
    return decode_mtp_bytes(path.read_bytes())
