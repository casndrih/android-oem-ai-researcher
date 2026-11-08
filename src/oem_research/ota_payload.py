"""Minimal Android OTA payload.bin parser/extractor.

Supports protobuf manifest operations REPLACE, REPLACE_BZ, REPLACE_XZ and ZERO.
Operations requiring source partitions or specialized diff codecs are reported as
unsupported and skipped. No device writes or update_engine execution occur.
"""
from pathlib import Path
import bz2, hashlib, lzma, struct

def _varint(buf, pos):
    value=0; shift=0
    while pos<len(buf) and shift<70:
        b=buf[pos]; pos+=1; value|=(b&0x7f)<<shift
        if not b&0x80: return value,pos
        shift+=7
    raise ValueError("Malformed protobuf varint")

def _fields(buf):
    pos=0
    while pos<len(buf):
        key,pos=_varint(buf,pos); num,wire=key>>3,key&7
        if not num: raise ValueError("Invalid protobuf field number")
        if wire==0: value,pos=_varint(buf,pos)
        elif wire==1:
            if pos+8>len(buf): raise ValueError("Truncated protobuf fixed64")
            value=buf[pos:pos+8]; pos+=8
        elif wire==2:
            n,pos=_varint(buf,pos)
            if n>len(buf)-pos: raise ValueError("Truncated protobuf length-delimited field")
            value=buf[pos:pos+n]; pos+=n
        elif wire==5:
            if pos+4>len(buf): raise ValueError("Truncated protobuf fixed32")
            value=buf[pos:pos+4]; pos+=4
        else: raise ValueError(f"Unsupported protobuf wire type {wire}")
        yield num,wire,value

def _extents(data):
    out=[]
    for n,w,v in _fields(data):
        if n==1: start=v
        elif n==2: count=v
    if "start" not in locals() or "count" not in locals(): raise ValueError("Invalid OTA extent")
    return (start,count)

def _operation(data):
    result={"type":None,"data_offset":0,"data_length":0,"dst_extents":[],"data_hash":None}
    for n,w,v in _fields(data):
        if n==1: result["type"]=v
        elif n==2: result["data_offset"]=v
        elif n==3: result["data_length"]=v
        elif n==6: result["dst_extents"].append(_extents(v))
        elif n==8: result["data_hash"]=v
    return result

def _partition(data):
    p={"name":None,"operations":[]}
    for n,w,v in _fields(data):
        if n==1: p["name"]=v.decode("utf-8","replace")
        elif n==5: p["operations"].append(_operation(v))
    return p

def parse_manifest(data):
    manifest={"block_size":4096,"partitions":[]}
    for n,w,v in _fields(data):
        if n==3: manifest["block_size"]=v
        elif n==13: manifest["partitions"].append(_partition(v))
    if manifest["block_size"]<=0 or manifest["block_size"]>1024*1024: raise ValueError("Invalid OTA block size")
    return manifest

def inspect_payload(path: Path) -> dict:
    path=Path(path)
    with path.open("rb") as f:
        h=f.read(20)
        if len(h)<20 or h[:4]!=b"CrAU": raise ValueError("Not an Android OTA payload.bin")
        version,manifest_size=struct.unpack(">QQ",h[4:20])
        sig_size=struct.unpack(">I",f.read(4))[0] if version>=2 else 0
        if manifest_size>64*1024*1024 or sig_size>16*1024*1024: raise ValueError("OTA metadata exceeds safety limits")
        manifest_bytes=f.read(manifest_size)
        if len(manifest_bytes)!=manifest_size: raise ValueError("Truncated OTA manifest")
        manifest=parse_manifest(manifest_bytes)
        data_start=20+(4 if version>=2 else 0)+manifest_size+sig_size
        f.seek(0,2); total=f.tell()
    ops=0
    for part in manifest["partitions"]:
        for op in part["operations"]:
            ops+=1
            if op["data_offset"]+op["data_length"]>total-data_start: raise ValueError("OTA operation data exceeds payload bounds")
    return {"version":version,"manifest_size":manifest_size,"metadata_signature_size":sig_size,"data_offset":data_start,"block_size":manifest["block_size"],"partitions":[{"name":p["name"],"operations":len(p["operations"])} for p in manifest["partitions"]],"operation_count":ops}

def extract_payload(path: Path, destination: Path) -> list[dict]:
    path,destination=Path(path),Path(destination)
    meta=inspect_payload(path)
    with path.open("rb") as f:
        f.seek(20); version=meta["version"]
        if version>=2: f.read(4)
        manifest=parse_manifest(f.read(meta["manifest_size"]))
        f.seek(0,2); total=f.tell()
    destination.mkdir(parents=True,exist_ok=True); results=[]
    with path.open("rb") as src:
        for part in manifest["partitions"]:
            if not part["name"]: continue
            safe="".join(c if c.isalnum() or c in "-_." else "_" for c in part["name"])
            target=destination/f"{safe}.img"; block=manifest["block_size"]
            max_end=max((start+count for op in part["operations"] for start,count in op["dst_extents"]),default=0)
            if max_end*block>16*1024**3: raise ValueError(f"Partition {safe} exceeds 16 GiB safety limit")
            with target.open("wb") as out:
                out.truncate(max_end*block)
                for op in part["operations"]:
                    typ=op["type"]
                    if typ not in (0,1,6,8): continue
                    offset=meta["data_offset"]+op["data_offset"]
                    if offset+op["data_length"]>total: raise ValueError("OTA operation data out of bounds")
                    src.seek(offset); raw=src.read(op["data_length"])
                    if len(raw)!=op["data_length"]: raise ValueError("Truncated OTA operation data")
                    if op["data_hash"] and hashlib.sha256(raw).digest()!=op["data_hash"]: raise ValueError("OTA operation data hash mismatch")
                    if typ==0: decoded=raw
                    elif typ==1: decoded=bz2.decompress(raw)
                    else: decoded=b""
                    expected=sum(count for _,count in op["dst_extents"])*block
                    if typ in (0,1) and len(decoded)!=expected: raise ValueError(f"Decoded OTA operation length mismatch in {safe}")
                    cursor=0
                    for start,count in op["dst_extents"]:
                        size=count*block
                        if typ==6: continue
                        out.seek(start*block); out.write(decoded[cursor:cursor+size]); cursor+=size
            results.append({"partition":part["name"],"file":str(target),"size":target.stat().st_size,"note":"REPLACE/REPLACE_BZ/REPLACE_XZ/ZERO operations applied; unsupported delta codecs skipped"})
    return results
