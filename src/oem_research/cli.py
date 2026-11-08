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

def main():
    p=argparse.ArgumentParser(prog="droidsec")
    sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("inspect"); a.add_argument("firmware",type=Path); a.add_argument("--out",type=Path,default=Path("reports"))
    b=sub.add_parser("partitions"); b.add_argument("directory",type=Path); b.add_argument("--out",type=Path,default=Path("reports"))
    c=sub.add_parser("plan"); c.add_argument("question")
    up=sub.add_parser("unisoc"); ups=up.add_subparsers(dest="action",required=True)
    upi=ups.add_parser("inspect"); upi.add_argument("pac",type=Path)
    upe=ups.add_parser("extract"); upe.add_argument("pac",type=Path); upe.add_argument("destination",type=Path)
    mt=sub.add_parser("mtk"); mt.add_argument("source",type=Path); mt.add_argument("destination",type=Path); mt.add_argument("--scatter",type=Path)
    qc=sub.add_parser("qualcomm"); qc.add_argument("source",type=Path); qc.add_argument("destination",type=Path); qc.add_argument("--rawprogram",type=Path)
    sub.add_parser("vendors")
    args=p.parse_args()
    if args.cmd=="vendors": print(VENDORS); return
    if args.cmd=="plan": print(make_plan(args.question)); return
    if args.cmd=="inspect":
        data={"firmware":str(args.firmware),"inventory":inventory([args.firmware])}
        try: data["archive_entries"]=list_archive(args.firmware)
        except ValueError: data["archive_entries"]=[]
        write_report(data,args.out)
    elif args.cmd=="partitions": write_report({"partitions":inspect_partitions(args.directory)},args.out)
    elif args.cmd=="unisoc":
        result=inspect_pac(args.pac) if args.action=="inspect" else extract_pac(args.pac,args.destination)
        print(result)
    elif args.cmd=="mtk": print(extract_mtk(args.source,args.destination,args.scatter))
    elif args.cmd=="qualcomm": print(extract_qualcomm(args.source,args.destination,args.rawprogram))

if __name__=="__main__": main()
