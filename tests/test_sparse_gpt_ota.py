import struct
from oem_research.sparse import expand_sparse
from oem_research.gpt import inspect_gpt
from oem_research.ota_payload import parse_manifest, _varint

def test_sparse_raw_expansion(tmp_path):
    src=tmp_path/"in.sparse"; dst=tmp_path/"out.img"
    data=b"ABCD"
    header=struct.pack("<IHHHHIIII",0xED26FF3A,1,0,28,12,4,1,1,0)
    chunk=struct.pack("<HHII",0xCAC1,0,1,16)+data
    src.write_bytes(header+chunk)
    result=expand_sparse(src,dst)
    assert dst.read_bytes()==data and result["size"]==4

def test_sparse_rejects_bad_magic(tmp_path):
    p=tmp_path/"bad"; p.write_bytes(b"\0"*40)
    try: expand_sparse(p,tmp_path/"out")
    except ValueError: pass
    else: assert False

def test_gpt_rejects_missing_signature(tmp_path):
    p=tmp_path/"disk.img"; p.write_bytes(b"\0"*4096)
    try: inspect_gpt(p)
    except ValueError: pass
    else: assert False

def test_payload_manifest_defaults():
    assert parse_manifest(b"")["block_size"]==4096
