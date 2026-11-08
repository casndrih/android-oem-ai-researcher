"""Bounded PCAP/PCAPNG reader and USBPcap payload extractor.

Supports classic PCAP and common PCAPNG blocks with LINKTYPE_USBPCAP (249).
No packet transmission, device access, or third-party dissector is invoked.
"""
from __future__ import annotations
from pathlib import Path
import struct

MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_PACKETS = 2_000_000
MAX_PACKET_BYTES = 16 * 1024 * 1024
USBPCAP_LINKTYPE = 249

def _classic(data):
    magic=data[:4]
    formats={
      b"\xd4\xc3\xb2\xa1":("<",False), b"\xa1\xb2\xc3\xd4":(">",False),
      b"\x4d\x3c\xb2\xa1":("<",True), b"\xa1\xb2\x3c\x4d":(">",True)}
    if magic not in formats: return None
    endian,nano=formats[magic]
    if len(data)<24: raise ValueError("Truncated PCAP global header")
    _,major,minor,_,_,snaplen,linktype=struct.unpack_from(endian+"IHHIIII",data,0)
    if major!=2 or snaplen>MAX_PACKET_BYTES: raise ValueError("Unsupported PCAP version or snap length")
    packets=[]; off=24
    while off<len(data):
        if len(packets)>=MAX_PACKETS: raise ValueError("PCAP packet-count limit exceeded")
        if len(data)-off<16: raise ValueError("Truncated PCAP packet header")
        sec,frac,caplen,origlen=struct.unpack_from(endian+"IIII",data,off); off+=16
        if caplen>MAX_PACKET_BYTES or caplen>len(data)-off: raise ValueError("Invalid/truncated PCAP packet data")
        packets.append({"timestamp":sec+(frac/(1_000_000_000 if nano else 1_000_000)),"data":data[off:off+caplen],"original_length":origlen})
        off+=caplen
    return linktype,packets,"pcap"

def _pcapng(data):
    if data[:4]!=b"\x0a\x0d\x0d\x0a": return None
    off=0; endian=None; interfaces=[]; packets=[]; sections=0
    while off<len(data):
        if len(data)-off<12: raise ValueError("Truncated PCAPNG block")
        if data[off:off+4]==b"\x0a\x0d\x0d\x0a":
            bom=data[off+8:off+12]
            endian="<" if bom==b"\x4d\x3c\x2b\x1a" else ">" if bom==b"\x1a\x2b\x3c\x4d" else None
            if endian is None: raise ValueError("Invalid PCAPNG byte-order magic")
            sections+=1; interfaces=[]
        if endian is None: raise ValueError("PCAPNG section header missing")
        block_type,total=struct.unpack_from(endian+"II",data,off)
        if total<12 or total%4 or total>len(data)-off: raise ValueError("Invalid PCAPNG block length")
        block=data[off:off+total]
        if struct.unpack_from(endian+"I",block,total-4)[0]!=total: raise ValueError("PCAPNG block length trailer mismatch")
        body=block[8:-4]
        if block_type==1: # Interface Description Block
            if len(body)<8: raise ValueError("Truncated PCAPNG interface block")
            link,_reserved,snap=struct.unpack_from(endian+"HHI",body,0)
            interfaces.append({"linktype":link,"snaplen":snap})
        elif block_type==6: # Enhanced Packet Block
            if len(body)<20: raise ValueError("Truncated PCAPNG enhanced packet block")
            iid,hi,lo,caplen,orig=struct.unpack_from(endian+"IIIII",body,0)
            if iid>=len(interfaces) or caplen>MAX_PACKET_BYTES or caplen>len(body)-20: raise ValueError("Invalid PCAPNG packet reference/length")
            packets.append({"timestamp":((hi<<32)|lo)/1_000_000,"data":body[20:20+caplen],"original_length":orig,"interface_id":iid})
        elif block_type==3: # Simple Packet Block
            if len(body)<4 or not interfaces: raise ValueError("Invalid PCAPNG simple packet block")
            orig=struct.unpack_from(endian+"I",body,0)[0]; iid=0
            cap=min(orig,len(body)-4,interfaces[iid]["snaplen"] or MAX_PACKET_BYTES)
            packets.append({"timestamp":None,"data":body[4:4+cap],"original_length":orig,"interface_id":iid})
        if len(packets)>MAX_PACKETS: raise ValueError("PCAPNG packet-count limit exceeded")
        off+=total
    if sections==0: raise ValueError("No PCAPNG section header")
    return interfaces,packets

def _usbpcap(packet):
    if len(packet)<27: return None,{"issue":"usbpcap-short-header"}
    hlen=struct.unpack_from("<H",packet,0)[0]
    if hlen<27 or hlen>len(packet): return None,{"issue":"usbpcap-invalid-header-length","header_length":hlen}
    irp=struct.unpack_from("<Q",packet,2)[0]
    status=struct.unpack_from("<I",packet,10)[0]
    function=struct.unpack_from("<H",packet,14)[0]
    info=packet[16]; bus,device=struct.unpack_from("<HH",packet,17)
    endpoint,transfer=packet[21],packet[22]
    data_len=struct.unpack_from("<I",packet,23)[0]
    if data_len>len(packet)-hlen: return None,{"issue":"usbpcap-truncated-transfer","declared":data_len,"available":len(packet)-hlen}
    payload=packet[hlen:hlen+data_len]
    meta={"irp_id":irp,"status":status,"function":function,"bus":bus,"device":device,
          "endpoint":endpoint&0x0f,"direction":"in" if endpoint&0x80 else "out",
          "transfer_type":{0:"isochronous",1:"interrupt",2:"control",3:"bulk"}.get(transfer,"unknown"),
          "data_length":data_len,"payload":payload}
    return meta,None

def inspect_capture(path: Path, protocol="both", max_bytes=MAX_CAPTURE_BYTES):
    path=Path(path); size=path.stat().st_size
    if path.is_symlink() or size>max_bytes: raise ValueError("Capture must be a regular file within the configured size limit")
    data=path.read_bytes()
    classic=_classic(data)
    if classic:
        link,packets,fmt=classic; interfaces=[{"linktype":link,"snaplen":None}]
    else:
        ng=_pcapng(data)
        if not ng: raise ValueError("Unsupported capture: expected classic PCAP or PCAPNG")
        interfaces,packets=ng; fmt="pcapng"
    usb_packets=[]; issues=[]; streams={}
    for index,p in enumerate(packets):
        iid=p.get("interface_id",0)
        if iid>=len(interfaces): issues.append({"packet":index,"issue":"unknown-interface"}); continue
        link=interfaces[iid]["linktype"]
        if link!=USBPCAP_LINKTYPE: continue
        meta,error=_usbpcap(p["data"])
        if error: issues.append({"packet":index,**error}); continue
        payload=meta.pop("payload")
        meta.update({"packet":index,"timestamp":p.get("timestamp"),"payload_preview_hex":payload[:24].hex()})
        usb_packets.append(meta)
        # Only bulk endpoint payloads are candidates; keep bus/device/endpoint/direction separate.
        if meta["transfer_type"]=="bulk" and payload:
            key=(meta["bus"],meta["device"],meta["endpoint"],meta["direction"])
            streams.setdefault(key,bytearray()).extend(payload)
    from .mtp_trace import decode_mtp_bytes
    from .adb_trace import decode_adb_bytes
    decoded=[]
    for key,blob in streams.items():
        if protocol in ("both","mtp"):
            result=decode_mtp_bytes(bytes(blob))
            if result["summary"]["container_count"]:
                decoded.append({"protocol":"MTP","bus":key[0],"device":key[1],"endpoint":key[2],"direction":key[3],"analysis":result})
        if protocol in ("both","adb"):
            result=decode_adb_bytes(bytes(blob))
            if result["summary"]["frame_count"]:
                decoded.append({"protocol":"ADB","bus":key[0],"device":key[1],"endpoint":key[2],"direction":key[3],"analysis":result})
    return {"capture":str(path),"format":fmt,"interfaces":interfaces,"packet_count":len(packets),
            "usbpcap_packet_count":len(usb_packets),"usbpcap_packets":usb_packets,
            "decoded_streams":decoded,"issues":issues,
            "limitations":["Only LINKTYPE_USBPCAP (249) is decoded; other link types are inventoried but not dissected.",
            "USB bulk payload bytes are concatenated per endpoint/direction. USB URB request/response pairing and transfer fragmentation semantics are not fully reconstructed.",
            "MTP and ADB parsers are structural. A parse result is not proof of exploitability or compromise."]}
