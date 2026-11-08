from pathlib import Path
from .inventory import inventory
PARTITIONS=("boot","vendor_boot","init_boot","recovery","vbmeta","super","system","system_ext","vendor","product","odm","modem","radio","dtbo","userdata")

def inspect_partitions(root: Path):
    rows=inventory(p for p in Path(root).rglob("*") if p.is_file())
    for row in rows:
        n=Path(row["path"]).name.lower()
        row["partition_candidates"]=[part for part in PARTITIONS if part in n]
    return rows
