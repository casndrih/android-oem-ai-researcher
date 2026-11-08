# DroidSec AI — Android OEM Firmware Security Researcher

Python toolkit for evidence-led, offline Android OEM firmware analysis. It inventories firmware, identifies image formats, calculates SHA-256 hashes, extracts supported package payloads and creates reports.

## v0.3 extraction adapters

### Unisoc / Spreadtrum PAC
    droidsec unisoc inspect firmware.pac
    droidsec unisoc extract firmware.pac extracted/unisoc

Implements a validated PAC header/file-record parser for the documented PAC layout. PAC revisions vary; malformed or incompatible layouts fail closed.

### MediaTek (MTK)
    droidsec mtk ./firmware_directory ./extracted/mtk
    droidsec mtk firmware_package.zip ./extracted/mtk
    droidsec mtk ./firmware_directory ./extracted/mtk --scatter ./MTK_Android_scatter.txt

Parses scatter partition records and extracts referenced image files marked for download. Directory and ZIP packages are supported. Scatter XML variants and vendor-specific wrappers are not yet supported.

### Qualcomm QFIL / Firehose
    droidsec qualcomm ./QFIL_Firmware ./extracted/qualcomm
    droidsec qualcomm firmware_package.zip ./extracted/qualcomm
    droidsec qualcomm ./QFIL_Firmware ./extracted/qualcomm --rawprogram ./rawprogram0.xml

Parses rawprogram XML and extracts referenced images. Patch XML is not executed; Firehose programmers are never launched. Sparse-image reassembly is not included yet.

## Other commands
    droidsec vendors
    droidsec inspect /path/to/firmware.zip --out reports
    droidsec partitions /path/to/extracted/images --out reports
    droidsec plan "Review boot chain and vendor partition"

## Install on Windows 11 / WSL2 Ubuntu
    sudo apt update
    sudo apt install -y python3 python3-venv python3-pip git
    git clone https://github.com/casndrih/android-oem-ai-researcher.git
    cd android-oem-ai-researcher
    git checkout develop
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e '.[dev]'
    pytest

## GLM API
Install the optional dependency with `pip install -e '.[ai]'`, then set `OPENAI_API_KEY` and `OPENAI_BASE_URL`. Never commit credentials. Model output is advisory and must be grounded in collected evidence.

## Safety and limitations
All extractors operate offline on local files. No device connection, flashing, bootloader unlocking, exploitation, programmer execution, or partition writes are performed. Extraction support is format-revision dependent; validate against authorized real firmware samples before relying on results. A successful file extraction does not establish firmware authenticity or safety.
