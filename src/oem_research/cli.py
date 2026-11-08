import argparse
import csv
import json
from pathlib import Path
from .archive import list_archive
from .inventory import inventory
from .partitions import inspect_partitions
from .research import make_plan
from .vendors import VENDORS
from .report import write_report
from .unisoc_pac import inspect_pac, extract_pac
from .mtk import extract_mtk
from .qualcomm import extract_qualcomm
from .sparse import expand_sparse
from .gpt import inspect_gpt, extract_gpt_partitions
from .ota_payload import inspect_payload, extract_payload
from .super_image import unpack_super
from .device_fingerprint import fingerprint_firmware
from .usb_security import analyze_usb_security

def main():
    p = argparse.ArgumentParser(prog="droidsec")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("inspect")
    a.add_argument("firmware", type=Path)
    a.add_argument("--out", type=Path, default=Path("reports"))
    b = sub.add_parser("partitions")
    b.add_argument("directory", type=Path)
    b.add_argument("--out", type=Path, default=Path("reports"))
    c = sub.add_parser("plan")
    c.add_argument("question")
    fp = sub.add_parser("fingerprint", help="Identify likely OEM/device from extracted firmware properties")
    fp.add_argument("directory", type=Path)
    fp.add_argument("--out", type=Path, default=Path("reports"))
    sec = sub.add_parser("security", help="Static ADB/MTP configuration triage; no live exploitation")
    sec.add_argument("directory", type=Path)
    sec.add_argument("--out", type=Path, default=Path("reports"))
    sec.add_argument("--ai", action="store_true", help="Ask configured OpenAI-compatible model to analyze collected evidence")
    dr = sub.add_parser("device-report", help="Build a device-specific ADB/MTP/SELinux/CVE report")
    dr.add_argument("directory", type=Path)
    dr.add_argument("--cve-json", type=Path, help="Local NVD CVE JSON 2.0 export")
    dr.add_argument("--components-json", type=Path, help="Optional JSON component inventory with name/version and optional CPE")
    dr.add_argument("--ai", action="store_true", help="Add GLM/OpenAI-compatible evidence assessment")
    dr.add_argument("--out", type=Path, default=Path("reports/device-security"))

    se = sub.add_parser("selinux-compiled", help="Query an explicitly supplied compiled SELinux policy using SETools")
    se.add_argument("policy", type=Path); se.add_argument("--timeout", type=int, default=30)
    se.add_argument("--out", type=Path, default=Path("reports/selinux-compiled"))
    mtp = sub.add_parser("mtp-trace", help="Decode a raw MTP container stream from an authorized capture")
    mtp.add_argument("capture", type=Path); mtp.add_argument("--out", type=Path, default=Path("reports/mtp-trace"))
    adb = sub.add_parser("adb-trace", help="Decode a raw ADB transport stream from an authorized capture")
    adb.add_argument("capture", type=Path); adb.add_argument("--out", type=Path, default=Path("reports/adb-trace"))

    up = sub.add_parser("unisoc")
    ups = up.add_subparsers(dest="action", required=True)
    upi = ups.add_parser("inspect"); upi.add_argument("pac", type=Path)
    upe = ups.add_parser("extract"); upe.add_argument("pac", type=Path); upe.add_argument("destination", type=Path)

    mt = sub.add_parser("mtk")
    mt.add_argument("source", type=Path); mt.add_argument("destination", type=Path); mt.add_argument("--scatter", type=Path)
    qc = sub.add_parser("qualcomm")
    qc.add_argument("source", type=Path); qc.add_argument("destination", type=Path); qc.add_argument("--rawprogram", type=Path)

    sp = sub.add_parser("sparse")
    sp.add_argument("image", type=Path); sp.add_argument("output", type=Path)
    gp = sub.add_parser("gpt")
    gp.add_argument("image", type=Path); gp.add_argument("--sector-size", type=int, default=512)
    gp.add_argument("--extract", type=Path); gp.add_argument("--csv", type=Path, help="Write GPT partition inventory as CSV")
    su = sub.add_parser("super")
    su.add_argument("image", type=Path); su.add_argument("destination", type=Path); su.add_argument("--timeout", type=int, default=600)
    ot = sub.add_parser("ota")
    ots = ot.add_subparsers(dest="action", required=True)
    oti = ots.add_parser("inspect"); oti.add_argument("payload", type=Path)
    ote = ots.add_parser("extract"); ote.add_argument("payload", type=Path); ote.add_argument("destination", type=Path)
    sub.add_parser("vendors")

    args = p.parse_args()
    if args.cmd == "vendors":
        print(VENDORS); return
    if args.cmd == "plan":
        print(make_plan(args.question)); return
    if args.cmd == "inspect":
        data = {"firmware": str(args.firmware), "inventory": inventory([args.firmware])}
        try: data["archive_entries"] = list_archive(args.firmware)
        except ValueError: data["archive_entries"] = []
        write_report(data, args.out)
    elif args.cmd == "partitions":
        write_report({"partitions": inspect_partitions(args.directory)}, args.out)
    elif args.cmd == "fingerprint":
        data = fingerprint_firmware(args.directory)
        write_report(data, args.out)
        print(json.dumps(data, indent=2))
    elif args.cmd == "security":
        data = analyze_usb_security(args.directory)
        if args.ai:
            from .glm import summarize
            data["ai_assessment"] = summarize(data)
        write_report(data, args.out)
        print(json.dumps(data, indent=2))
    elif args.cmd == "selinux-compiled":
        from .setools_adapter import inspect_compiled_policy
        result = inspect_compiled_policy(args.policy, args.timeout)
        write_report(result, args.out)
        print(json.dumps(result, indent=2))
    elif args.cmd == "mtp-trace":
        from .mtp_trace import decode_mtp_file
        result = decode_mtp_file(args.capture)
        write_report(result, args.out)
        print(json.dumps(result, indent=2))
    elif args.cmd == "adb-trace":
        from .adb_trace import decode_adb_file
        result = decode_adb_file(args.capture)
        write_report(result, args.out)
        print(json.dumps(result, indent=2))

    elif args.cmd == "unisoc":
        result = inspect_pac(args.pac) if args.action == "inspect" else extract_pac(args.pac, args.destination)
        print(result)
    elif args.cmd == "mtk":
        print(extract_mtk(args.source, args.destination, args.scatter))
    elif args.cmd == "qualcomm":
        print(extract_qualcomm(args.source, args.destination, args.rawprogram))
    elif args.cmd == "sparse":
        print(expand_sparse(args.image, args.output))
    elif args.cmd == "gpt":
        result = inspect_gpt(args.image, args.sector_size)
        if args.csv:
            args.csv.parent.mkdir(parents=True, exist_ok=True)
            fields = ["index", "name", "type_guid", "guid", "first_lba", "last_lba", "offset", "size", "attributes"]
            with args.csv.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                writer.writerows(result["partitions"])
        if args.extract:
            result["extracted"] = extract_gpt_partitions(args.image, args.extract, args.sector_size)
        print(json.dumps(result, indent=2))
    elif args.cmd == "super":
        print(unpack_super(args.image, args.destination, args.timeout))
    elif args.cmd == "ota":
        result = inspect_payload(args.payload) if args.action == "inspect" else extract_payload(args.payload, args.destination)
        print(result)

if __name__ == "__main__":
    main()
