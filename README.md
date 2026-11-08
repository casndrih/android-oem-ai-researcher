# DroidSec AI — Android OEM Firmware Security Researcher

Python foundation for evidence-led static analysis of Android OEM firmware. It inventories packages and partition images, identifies common formats, records SHA-256 hashes, creates research plans, and optionally summarizes evidence using an authenticated OpenAI-compatible GLM API.

## Identification scope
Samsung Odin TAR/TAR.MD5; Huawei/Honor UPDATE.APP candidates; ZTE OEM ZIP candidates; Qualcomm/QFIL and Unisoc PAC candidates; Android OTA ZIP and payload.bin; boot, vendor_boot, init_boot, recovery, vbmeta/AVB, sparse images, super, system, vendor, product, odm, modem/baseband, dtbo; ELF and SquashFS.

Detection is not equivalent to full extraction. Proprietary vendor parsers require tested adapters and real firmware fixtures; full support is not claimed here.

## Safety
Static analysis is read-only by default. Archive extraction rejects path traversal and skips links. Dynamic testing requires explicit approval. Flashing, device writes, bootloader unlocking and exploitation are blocked. Only analyze firmware and devices you are authorized to examine.

## WSL2 Ubuntu installation
    sudo apt update
    sudo apt install -y python3 python3-venv python3-pip git
    git clone https://github.com/casndrih/android-oem-ai-researcher.git
    cd android-oem-ai-researcher
    git checkout develop
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e '.[dev]'
    pytest

## Commands
    droidsec vendors
    droidsec inspect /path/to/firmware.zip --out reports
    droidsec partitions /path/to/extracted/images --out reports
    droidsec plan "Review boot chain and vendor partition"

Reports are generated in JSON and Markdown. GLM support is optional: install with pip install -e '.[ai]', set OPENAI_API_KEY and OPENAI_BASE_URL, and never commit credentials. Model output is advisory and must be grounded in supplied evidence.

This is a research foundation, not a universal firmware unpacker or automated vulnerability scanner.
