import argparse
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
    gp.add_argument("image", type=Path); gp.add_argument("--sector-size", type=int, default=512); gp.add_argument("--extract", type=Path)
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
        result = extract_gpt_partitions(args.image, args.extract, args.sector_size) if args.extract else inspect_gpt(args.image, args.sector_size)
        print(result)
    elif args.cmd == "ota":
        result = inspect_payload(args.payload) if args.action == "inspect" else extract_payload(args.payload, args.destination)
        print(result)

if __name__ == "__main__":
    main()
