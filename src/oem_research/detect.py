from pathlib import Path
SIGNATURES = [(b"ANDROID!", "android-boot-image"), (b"AVB0", "android-vbmeta-avb"), (b"CrAU", "android-ota-payload"), (b"hsqs", "squashfs"), (b"\x7fELF", "elf"), (b"UBI#", "ubi")]

def identify(path: Path) -> list[str]:
    name=path.name.lower(); found=[]
    if name.endswith((".tar.md5",".tar")): found.append("samsung-odin-tar-candidate")
    if name.endswith(".pac"): found.append("unisoc-pac-candidate")
    if name.endswith(".app"): found.append("huawei-honor-update-app-candidate")
    if name.endswith((".zip",".ozip")): found.append("android-ota-or-oem-zip-candidate")
    if name.endswith((".mbn",".elf")): found.append("modem-or-elf-component-candidate")
    try:
        with path.open("rb") as f: head=f.read(4096)
        for magic,label in SIGNATURES:
            if head.startswith(magic) and label not in found: found.append(label)
        if head[:4]==b"\x3a\xff\x26\xed": found.append("android-sparse-image")
    except OSError: found.append("unreadable")
    return found or ["unknown"]
