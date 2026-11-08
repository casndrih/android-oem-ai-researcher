import struct
from pathlib import Path
from oem_research.mtk import parse_scatter_text
from oem_research.qualcomm import parse_rawprogram
from oem_research.unisoc_pac import inspect_pac

def test_mtk_scatter_parse():
    rows=parse_scatter_text("- partition_index: SYS0\n  partition_name: boot\n  file_name: boot.img\n  is_download: true\n  partition_size: 0x1000")
    assert rows[0]["partition_name"]=="boot"
    assert rows[0]["file_name"]=="boot.img"

def test_qcom_rawprogram_parse():
    rows=parse_rawprogram('<data><program filename="boot.img" label="boot" start_sector="10" num_sectors="20"/></data>')
    assert rows[0]["label"]=="boot"
    assert rows[0]["filename"]=="boot.img"

def test_pac_rejects_short_file(tmp_path):
    p=tmp_path/"bad.pac"; p.write_bytes(b"PAC")
    try: inspect_pac(p)
    except ValueError: pass
    else: assert False, "short PAC should be rejected"
