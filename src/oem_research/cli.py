import argparse
from pathlib import Path
from .archive import list_archive
from .inventory import inventory
from .partitions import inspect_partitions
from .research import make_plan
from .vendors import VENDORS
from .report import write_report

def main():
    p=argparse.ArgumentParser(prog="droidsec"); sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("inspect"); a.add_argument("firmware",type=Path); a.add_argument("--out",type=Path,default=Path("reports"))
    b=sub.add_parser("partitions"); b.add_argument("directory",type=Path); b.add_argument("--out",type=Path,default=Path("reports"))
    c=sub.add_parser("plan"); c.add_argument("question"); sub.add_parser("vendors")
    args=p.parse_args()
    if args.cmd=="vendors": print(VENDORS); return
    if args.cmd=="plan": print(make_plan(args.question)); return
    if args.cmd=="inspect":
        data={"firmware":str(args.firmware),"inventory":inventory([args.firmware])}
        try: data["archive_entries"]=list_archive(args.firmware)
        except ValueError: data["archive_entries"]=[]
        write_report(data,args.out)
    elif args.cmd=="partitions": write_report({"partitions":inspect_partitions(args.directory)},args.out)

if __name__=="__main__": main()
