import struct
from oem_research.capture import inspect_capture
from oem_research.bulletin import analyze_bulletin

def _pcap(linktype, packet):
    return (struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,linktype)+
            struct.pack("<IIII",1,2,len(packet),len(packet))+packet)

def _usb_packet(payload):
    h=struct.pack("<HQIHBHHBBI",27,1,0,0,0,1,4,0x81,3,len(payload))
    return h+payload

def test_classic_usbpcap_extracts_bulk_packet(tmp_path):
    payload=b"\x0c\x00\x00\x00"+b"\x01\x00\x01\x10"+b"\x07\x00\x00\x00"
    f=tmp_path/"sample.pcap"; f.write_bytes(_pcap(249,_usb_packet(payload)))
    result=inspect_capture(f,protocol="mtp")
    assert result["usbpcap_packet_count"]==1
    assert result["decoded_streams"][0]["protocol"]=="MTP"

def test_pcapng_interface_and_packet(tmp_path):
    # little-endian SHB, IDB (USBPcap), EPB (one packet)
    shb_body=struct.pack("<IHHq",0x1a2b3c4d,1,0,-1)
    shb=struct.pack("<II",0x0a0d0d0a,28)+shb_body+struct.pack("<I",28)
    idb_body=struct.pack("<HHI",249,0,65535)
    idb=struct.pack("<II",1,20)+idb_body+struct.pack("<I",20)
    packet=_usb_packet(b"")
    pad=packet+b"\0"*((4-len(packet)%4)%4)
    epb_body=struct.pack("<IIIII",0,0,1000000,len(packet),len(packet))+pad
    total=12+len(epb_body)
    epb=struct.pack("<II",6,total)+epb_body+struct.pack("<I",total)
    f=tmp_path/"sample.pcapng"; f.write_bytes(shb+idb+epb)
    result=inspect_capture(f)
    assert result["format"]=="pcapng" and result["packet_count"]==1

def test_bulletin_extracts_cve_ids(tmp_path):
    f=tmp_path/"bulletin.txt"; f.write_text("CVE-2025-12345 fixed; SPL 2025-03-05")
    result=analyze_bulletin(f)
    assert result["bulletin_cves"]==["CVE-2025-12345"]
