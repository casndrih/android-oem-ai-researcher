"""Read-only parser for concatenated Android Debug Bridge wire frames."""
from __future__ import annotations
from pathlib import Path
import struct

ADB_HEADER = struct.Struct("<6I")
ADB_COMMANDS = {b"CNXN": "connect", b"AUTH": "authentication", b"OPEN": "open",
                b"OKAY": "okay", b"WRTE": "write", b"CLSE": "close",
                b"SYNC": "sync", b"STLS": "tls-upgrade"}
MAX_ADB_PAYLOAD = 16 * 1024 * 1024
MAX_FRAMES = 100000

def decode_adb_bytes(data: bytes, max_payload: int = MAX_ADB_PAYLOAD) -> dict:
    frames, issues, offset = [], [], 0
    while offset < len(data):
        if len(frames) >= MAX_FRAMES:
            issues.append({"offset": offset, "issue": "frame-count-limit"}); break
        if len(data) - offset < ADB_HEADER.size:
            issues.append({"offset": offset, "issue": "truncated-header"}); break
        command, arg0, arg1, length, checksum, magic = ADB_HEADER.unpack_from(data, offset)
        name = struct.pack("<I", command)
        if magic != (command ^ 0xffffffff):
            issues.append({"offset": offset, "issue": "invalid-command-magic"}); break
        if length > max_payload:
            issues.append({"offset": offset, "issue": "payload-size-limit", "length": length}); break
        end = offset + ADB_HEADER.size + length
        if end > len(data):
            issues.append({"offset": offset, "issue": "truncated-payload", "declared": length,
                           "available": len(data) - offset - ADB_HEADER.size}); break
        payload = data[offset + ADB_HEADER.size:end]
        # ADB checksum is the unsigned byte sum for legacy protocol versions.
        checksum_valid = (sum(payload) & 0xffffffff) == checksum if length else checksum == 0
        frames.append({"offset": offset, "command": name.decode("ascii", "replace"),
                       "command_name": ADB_COMMANDS.get(name, "unknown"),
                       "arg0": arg0, "arg1": arg1, "payload_length": length,
                       "checksum_valid": checksum_valid,
                       "payload_preview": payload[:48].decode("utf-8", "replace") if name in (b"OPEN", b"CNXN", b"AUTH") else None})
        if not checksum_valid:
            issues.append({"offset": offset, "issue": "checksum-mismatch", "command": name.decode("ascii", "replace")})
        offset = end
    names = [x["command"] for x in frames]
    return {"protocol": "ADB", "input_bytes": len(data), "frames": frames, "issues": issues,
            "summary": {"frame_count": len(frames), "commands": names,
                        "auth_frames": names.count("AUTH"), "connect_frames": names.count("CNXN"),
                        "open_frames": names.count("OPEN"), "write_frames": names.count("WRTE"),
                        "close_frames": names.count("CLSE"), "malformed": bool(issues)},
            "limitations": ["Parses raw concatenated ADB transport frames, not PCAP/USBPcap framing.",
                            "Payloads are not executed; this parser cannot establish whether a host/device was compromised.",
                            "Checksum validation follows legacy ADB framing and may need protocol-version context for newer transports."]}

def decode_adb_file(path: Path, max_bytes: int = 256 * 1024 * 1024) -> dict:
    path = Path(path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"Input exceeds {max_bytes} byte limit")
    return decode_adb_bytes(path.read_bytes())
