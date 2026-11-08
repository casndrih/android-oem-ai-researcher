"""Android sparse image inspector and expander (RAW/FILL/DONT_CARE/CRC32)."""
from pathlib import Path
import struct, zlib

MAGIC=0xED26FF3A
RAW,FILL,DONT_CARE,CRC32=0xCAC1,0xCAC2,0xCAC3,0xCAC4

def expand_sparse(source: Path, destination: Path, *, max_output_bytes: int=16*1024**3) -> dict:
    source,destination=Path(source),Path(destination)
    with source.open("rb") as f:
        h=f.read(28)
        if len(h)!=28: raise ValueError("Truncated sparse header")
        magic,major,minor,file_hdr,chunk_hdr,block_size,total_blocks,total_chunks,checksum=struct.unpack("<IHHHHIIII",h)
        if magic!=MAGIC or major!=1: raise ValueError("Unsupported Android sparse image")
        if block_size==0 or block_size%4: raise ValueError("Invalid sparse block size")
        total_size=block_size*total_blocks
        if total_size>max_output_bytes: raise ValueError("Expanded image exceeds configured size limit")
        if file_hdr<28 or chunk_hdr<12: raise ValueError("Invalid sparse header sizes")
        f.seek(file_hdr)
        destination.parent.mkdir(parents=True,exist_ok=True)
        crc=0; written_blocks=0
        with destination.open("wb") as out:
            for index in range(total_chunks):
                ch=f.read(chunk_hdr)
                if len(ch)!=chunk_hdr: raise ValueError(f"Truncated chunk header {index}")
                kind,reserved,chunk_blocks,total_sz=struct.unpack("<HHII",ch[:12])
                expected=chunk_hdr
                out_bytes=chunk_blocks*block_size
                if written_blocks+chunk_blocks>total_blocks: raise ValueError("Chunk blocks exceed sparse header total")
                if kind==RAW:
                    expected+=out_bytes
                    if total_sz!=expected: raise ValueError("RAW chunk size mismatch")
                    remaining=out_bytes
                    while remaining:
                        b=f.read(min(1024*1024,remaining))
                        if not b: raise ValueError("Truncated RAW chunk")
                        out.write(b); crc=zlib.crc32(b,crc); remaining-=len(b)
                elif kind==FILL:
                    expected+=4
                    if total_sz!=expected: raise ValueError("FILL chunk size mismatch")
                    pattern=f.read(4)
                    if len(pattern)!=4: raise ValueError("Truncated FILL pattern")
                    piece=(pattern*((1024*1024)//4+1))[:min(1024*1024,out_bytes)]
                    remaining=out_bytes
                    while remaining:
                        b=piece[:min(len(piece),remaining)]
                        out.write(b); crc=zlib.crc32(b,crc); remaining-=len(b)
                elif kind==DONT_CARE:
                    if total_sz!=chunk_hdr: raise ValueError("DONT_CARE chunk size mismatch")
                    remaining=out_bytes
                    zero=b"\0"*(1024*1024)
                    while remaining:
                        b=zero[:min(len(zero),remaining)]
                        out.write(b); crc=zlib.crc32(b,crc); remaining-=len(b)
                elif kind==CRC32:
                    if chunk_blocks!=0 or total_sz!=chunk_hdr+4: raise ValueError("Invalid CRC32 chunk")
                    expected_crc=struct.unpack("<I",f.read(4))[0]
                    if expected_crc!=(crc&0xffffffff): raise ValueError("Sparse CRC32 chunk mismatch")
                else: raise ValueError(f"Unknown sparse chunk type 0x{kind:04x}")
                written_blocks+=chunk_blocks
            if written_blocks!=total_blocks: raise ValueError("Sparse block count mismatch")
            if checksum and checksum!=(crc&0xffffffff): raise ValueError("Sparse image checksum mismatch")
        if f.read(1): raise ValueError("Unexpected trailing bytes in sparse image")
    return {"output":str(destination),"size":total_size,"blocks":total_blocks,"block_size":block_size,"chunks":total_chunks,"crc32":f"{crc&0xffffffff:08x}"}
