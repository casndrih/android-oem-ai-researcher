# DroidSec AI — Android OEM Firmware Security Researcher

Python toolkit for evidence-led offline Android OEM firmware analysis and extraction.

## v0.4 capabilities

### Unisoc / Spreadtrum PAC
    droidsec unisoc inspect firmware.pac
    droidsec unisoc extract firmware.pac extracted/unisoc
PAC record layout is revision-dependent; unsupported revisions fail closed.

### MediaTek (MTK)
    droidsec mtk ./firmware_directory ./extracted/mtk
    droidsec mtk firmware_package.zip ./extracted/mtk
    droidsec mtk ./firmware_directory ./extracted/mtk --scatter ./MTK_scatter.txt
Parses scatter records and copies referenced partition images. Scatter XML variants/vendor wrappers remain unsupported.

### Qualcomm QFIL / Firehose
    droidsec qualcomm ./QFIL_Firmware ./extracted/qualcomm
    droidsec qualcomm firmware_package.zip ./extracted/qualcomm
    droidsec qualcomm ./QFIL_Firmware ./extracted/qualcomm --rawprogram ./rawprogram0.xml
Parses rawprogram XML and extracts referenced files. It does not execute Firehose programmers or apply patch XML.

### Android sparse image expansion
    droidsec sparse system.img system-expanded.img
Supports RAW, FILL, DONT_CARE and CRC32 chunks, with output-size and structural validation.

### GPT partition table inspection/extraction
    droidsec gpt disk.img
    droidsec gpt disk.img --sector-size 4096
    droidsec gpt disk.img --extract ./gpt_partitions
Reads GPT entries from a raw disk image and can extract the described partition ranges. It does not repair or modify the source disk.

### Android dynamic super image\n    droidsec super super.img ./super_partitions\nUses the separately installed AOSP `lpunpack` utility (must be on PATH) to extract logical partitions from a dynamic super image. The wrapper invokes it without a shell and enforces a timeout. Use a sandbox for untrusted firmware.\n\n### Android OTA payload.bin
    droidsec ota inspect payload.bin
    droidsec ota extract payload.bin ./ota_partitions
Reads the CrAU header and protobuf manifest. Extraction supports REPLACE, REPLACE_BZ, REPLACE_XZ and ZERO operations. Delta operations requiring source partitions and specialized codecs are skipped; this is not yet a complete update_engine implementation. Verify output images before further analysis.

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
Install `pip install -e '.[ai]'`, then set `OPENAI_API_KEY` and `OPENAI_BASE_URL`. Never commit credentials. Model output is advisory and must be grounded in collected evidence.

## Safety and limitations
All extractors operate offline on local files. No device connection, flashing, bootloader unlocking, exploitation, programmer execution, or partition writes are performed. Format support is revision-dependent; validate with authorized real firmware samples. This is a research toolkit, not a universal firmware unpacker.
