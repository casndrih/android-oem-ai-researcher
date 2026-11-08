import struct
from oem_research.mtp_trace import decode_mtp_bytes
from oem_research.adb_trace import decode_adb_bytes

def test_mtp_decodes_containers_and_flags_truncation():
    command = struct.pack("<IHHI", 12, 1, 0x1001, 7)
    event = struct.pack("<IHHI", 12, 4, 0x4002, 0)
    result = decode_mtp_bytes(command + event)
    assert result["summary"]["container_count"] == 2
    assert result["containers"][0]["transaction_id"] == 7
    assert not result["issues"]
    assert decode_mtp_bytes(command[:-1])["issues"][0]["issue"] == "truncated-header"

def test_mtp_rejects_oversized_container():
    data = struct.pack("<IHHI", 0xffffffff, 1, 0x1001, 1)
    assert decode_mtp_bytes(data)["issues"][0]["issue"] == "container-size-limit"

def test_adb_decodes_frame_and_validates_checksum():
    payload = b"host::features=shell_v2;"
    command = int.from_bytes(b"CNXN", "little")
    header = struct.pack("<6I", command, 0x01000001, 4096, len(payload),
                         sum(payload), command ^ 0xffffffff)
    result = decode_adb_bytes(header + payload)
    assert result["frames"][0]["command"] == "CNXN"
    assert result["frames"][0]["checksum_valid"]
    assert result["summary"]["connect_frames"] == 1

def test_adb_rejects_bad_magic_and_truncated_payload():
    command = int.from_bytes(b"OPEN", "little")
    bad = struct.pack("<6I", command, 1, 2, 0, 0, 0)
    assert decode_adb_bytes(bad)["issues"][0]["issue"] == "invalid-command-magic"
    good = struct.pack("<6I", command, 1, 2, 8, 0, command ^ 0xffffffff)
    assert decode_adb_bytes(good)["issues"][0]["issue"] == "truncated-payload"
