from pathlib import Path
import struct
import pytest
from oem_research.mtk import parse_scatter_text, extract_mtk
from oem_research.qualcomm import parse_rawprogram, extract_qualcomm
from oem_research.sparse import expand_sparse
from oem_research.ota_payload import parse_manifest, _fields

ROOT=Path(__file__).parent

def test_mtk_scatter_fixture_parses_boot_and_vbmeta():
    rows=parse_scatter_text((ROOT/"fixtures/mtk/MT6789_Android_scatter.txt").read_text())
    assert [r["partition_name"] for r in rows]==["boot","vbmeta"]
    assert all(r["is_download"]=="true" for r in rows)

def test_mtk_extraction_from_fixture_directory(tmp_path):
    fw=tmp_path/"fw"; fw.mkdir()
    (fw/"boot.img").write_bytes(b"BOOT")
    (fw/"vbmeta.img").write_bytes(b"AVB0")
    scatter=ROOT/"fixtures/mtk/MT6789_Android_scatter.txt"
    result=extract_mtk(fw,tmp_path/"out",scatter)
    assert len(result)==2
    assert (tmp_path/"out/boot.img").read_bytes()==b"BOOT"

def test_qualcomm_rawprogram_fixture_parses_rows():
    rows=parse_rawprogram((ROOT/"fixtures/qualcomm/rawprogram0.xml").read_text())
    assert [r["label"] for r in rows]==["PrimaryGPT","boot","vbmeta"]
    assert rows[1]["start_sector"]=="32768"

def test_qualcomm_extracts_only_referenced_files(tmp_path):
    fw=tmp_path/"qfil"; fw.mkdir()
    (fw/"boot.img").write_bytes(b"BOOT")
    (fw/"vbmeta.img").write_bytes(b"AVB0")
    xml=ROOT/"fixtures/qualcomm/rawprogram0.xml"
    result=extract_qualcomm(fw,tmp_path/"out",xml)
    assert len(result)==2
    assert (tmp_path/"out/vbmeta.img").read_bytes()==b"AVB0"

def test_qualcomm_rejects_path_traversal():
    with pytest.raises(ValueError):
        parse_rawprogram('<data><program filename="../evil.bin" label="bad"/></data>')

def test_sparse_rejects_excessive_output(tmp_path):
    p=tmp_path/"sparse"
    p.write_bytes(struct.pack("<IHHHHIIII",0xED26FF3A,1,0,28,12,4096,100,0,0))
    with pytest.raises(ValueError):
        expand_sparse(p,tmp_path/"out",max_output_bytes=4096)

def test_ota_manifest_default_block_size():
    assert parse_manifest(b"")["block_size"]==4096
