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


## Device identification and USB security triage

Run these commands against an **extracted firmware directory**:

```bash
droidsec fingerprint ./extracted_firmware --out reports/device
droidsec security ./extracted_firmware --out reports/usb-security
droidsec security ./extracted_firmware --ai --out reports/usb-security-ai
```

- **Device fingerprinting** reads Android property files such as `build.prop`, `default.prop`, and vendor/product property files. It reports manufacturer/brand, model, product/device codename, build fingerprint, Android version, platform and evidence file paths, with a confidence label. Exact model identity must be corroborated against trusted OEM metadata; firmware properties can be absent or spoofed.
- **GPT table output** validates the GPT header and partition-entry CRCs, then emits partition names, type/unique GUIDs, LBA ranges, offsets, sizes and attributes as JSON; `--csv` exports the partition inventory as a table. Extraction remains read-only against the source image.
- **ADB/MTP static review** scans extracted text configuration for ADB TCP listeners, debug/authentication properties, USB composition settings, MTP service references and related evidence. It generates findings with severity, evidence lines, explanations and hardening recommendations.
- **AI-assisted assessment** (`--ai`) sends the collected static evidence to the configured OpenAI-compatible model. The model must distinguish observations from hypotheses; its output is advisory and should be checked by a human researcher.

This does **not** claim to prove an exploit is present or exploitable. It does not connect to a phone, fuzz MTP, issue ADB commands, bypass pairing, or execute an exploit. Runtime validation belongs in an isolated, authorized test lab. Static configuration indicators can miss vulnerabilities or produce false positives.

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


## Regression fixtures and upstream format references

Small, hand-authored parser fixtures live under `tests/fixtures/`:
- `tests/fixtures/mtk/MT6789_Android_scatter.txt` — representative MediaTek scatter syntax.
- `tests/fixtures/qualcomm/rawprogram0.xml` — representative Qualcomm QFIL rawprogram syntax.

These are compact synthetic regression fixtures, **not OEM-distributed firmware dumps**. CI tests exercise parser behavior and safe extraction using generated image payloads. Large vendor firmware binaries are not committed to this repository.

Useful public upstream references for format validation:
- Unisoc PAC tooling and parser examples: https://github.com/DiegoPtit/unisoc_tools
- Qualcomm QFIL sparse-image tooling (Lenovo Tab4 8 Plus validation noted upstream): https://github.com/NHellFire/android-qfil-unsparse
- Android OTA payload dumper with Google Pixel OTA sample reference: https://github.com/ssut/payload-dumper-go
- Android OTA payload format schema: https://android.googlesource.com/platform/system/update_engine/+/master/update_metadata.proto

For large real-world OTA test data, Google publishes official device OTA packages at https://developers.google.com/android/ota. Download only the exact device package you intend to validate; these can be multi-gigabyte files.


See [`docs/REAL_FIRMWARE_VALIDATION.md`](docs/REAL_FIRMWARE_VALIDATION.md) for candidate public sources, provenance requirements, and the acceptance criteria for claiming real-firmware compatibility.


## Deep device security assessment

Build a combined device-specific report from an extracted firmware tree:

```bash
droidsec device-report ./extracted_firmware --out reports/device
droidsec device-report ./extracted_firmware --cve-json ./nvd-cves.json --out reports/device
droidsec device-report ./extracted_firmware --cve-json ./nvd-cves.json --ai --out reports/device-ai
```

The unified report includes:
- Device identity and evidence-backed fingerprint confidence.
- ADB and MTP source/configuration attack-surface references.
- SELinux source policy triage (permissive domains, wildcard-like allow rules, ADB/shell and USB/MTP policy references).
- Optional offline CVE candidate correlation against a user-supplied NVD JSON 2.0 export, using device identity tokens and CPE criteria.
- Optional GLM analysis through `OPENAI_BASE_URL`, `OPENAI_API_KEY` and the configured model. AI is instructed to separate confirmed evidence, hypotheses, false-positive possibilities and unknowns.

Install AI support with `pip install -e ".[ai]"`. Set `OPENAI_BASE_URL`, `OPENAI_API_KEY` and optionally adapt the model name in the report integration to your provider.

### CVE matching caveats

NVD JSON 2.0 exports can be obtained from the NVD data feeds/API and supplied locally. Current matching is deliberately candidate generation using device identity tokens against CPE criteria; it does not assert that a CVE affects a device. Validate exact model, Android release, kernel/vendor component version, affected version ranges, OEM backports and the OEM security bulletin. An Android security patch level is not sufficient by itself to infer all component fixes.

### Research foundations and external tools studied

- [libmtp](https://github.com/libmtp/libmtp) documents MTP initiator behavior, device quirks and Android responder references. DroidSec uses it as protocol context; it does not embed or fuzz libmtp.
- [Android frameworks/base](https://android.googlesource.com/platform/frameworks/base/) contains the Android framework-side MTP implementation; match the source revision to the firmware build before drawing conclusions.
- [FICS BigMAC](https://github.com/FICS/BigMAC) demonstrates firmware-oriented Android DAC/MAC/SELinux policy recovery and querying. It has substantial legacy build dependencies, so DroidSec implements a lightweight source triage and recommends SETools for authoritative compiled-policy queries.
- [SELinuxProject tools](https://github.com/SELinuxProject/selinux/wiki/Tools) documents SETools capabilities such as `seinfo`, `sesearch`, `sediff` and domain-transition analysis.
- [Android Security Bulletins](https://source.android.com/docs/security/bulletin/asb-overview) provide monthly patch-level and component vulnerability information; use OEM bulletins for vendor-specific backports.
- [AOSP system/core](https://android.googlesource.com/platform/system/core/) provides ADB daemon and USB composition implementation context. Always use a source revision corresponding to the target build.

The protocol inventory is static. It does not connect to USB devices, send ADB commands, fuzz MTP, bypass pairing, or execute exploits. SELinux text triage does not replace parsing the compiled policy with SETools. NVD CPE matches are candidates, not confirmed affected-device findings. Dynamic validation requires an isolated, authorized test device and explicit human approval.


## Captured MTP and ADB trace decoding

DroidSec can structurally decode **raw concatenated MTP containers** and **raw concatenated ADB transport frames** from authorized captures. It does not connect to a device, issue commands, fuzz, or exploit either protocol. USBPcap/pcapng encapsulation is not yet decoded; extract the raw protocol byte stream with a trusted capture tool first.

```bash
droidsec mtp-trace authorized-mtp-stream.bin --out reports/mtp
droidsec adb-trace authorized-adb-stream.bin --out reports/adb
```

The decoders validate lengths, frame boundaries, MTP transaction references, ADB command magic, payload bounds, and legacy checksums. Malformed input is reported as evidence rather than repaired. They are protocol-structure triage tools, not complete protocol conformance or exploitability tests.


## Compiled SELinux policy queries (optional SETools)

For an explicitly supplied compiled policy file, install SETools on the analysis host and run:

```bash
droidsec selinux-compiled ./vendor/etc/selinux/precompiled_sepolicy --out reports/selinux-compiled
```

The adapter invokes `seinfo --stats` and focused `sesearch` allow-rule queries for `adbd` and `mtp`, with no shell, a bounded timeout, and no policy modification. If SETools is absent, it reports that the optional tools are unavailable. Binary policy support depends on the SETools build and Android policy version; review output and errors rather than treating a successful parse as a runtime security verdict.


### Component-aware CVE correlation

An optional component inventory can be supplied to `device-report`:

```json
{
  "components": [
    {"name": "Android kernel", "version": "5.10.198", "cpe": "cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*"},
    {"name": "libmtp", "version": "1.1.20"}
  ]
}
```

Run `droidsec device-report ./firmware --cve-json ./nvd.json --components-json ./components.json --ai`. Numeric dotted component versions are compared with NVD inclusive/exclusive bounds. Non-numeric OEM build strings are marked unknown; a CPE/version candidate is not proof of vulnerability because vendor backports and product-specific patching must be checked.


## USBPcap capture ingestion and bulletin correlation

DroidSec accepts classic PCAP and PCAPNG files with USBPcap link type 249. It validates capture framing, extracts USB bulk payloads, separates streams by bus/device/endpoint/direction, and attempts structural MTP/ADB decoding. Other link types are inventoried but not dissected; URB pairing and all USB transfer edge cases are not yet reconstructed.

```bash
droidsec capture authorized-usb-capture.pcapng --protocol both --out reports/capture
```

For Android Security Bulletin correlation, save the official bulletin HTML or text locally and provide it to the device dossier:

```bash
droidsec device-report ./extracted_firmware --cve-json ./nvd.json \
  --components-json ./components.json --bulletin ./android-security-bulletin.html \
  --ai --out reports/device
```

The bulletin parser extracts CVE identifiers and date tokens and cross-references the existing NVD candidate set. It does not infer that a device is vulnerable merely because a CVE appears in a bulletin, or that a device is patched solely from its SPL. Official Android bulletin sources: https://source.android.com/docs/security/bulletin/asb-overview


## Local-first full firmware analysis (recommended for large samples)

Large firmware packages do not need to be uploaded to ChatGPT or GitHub. Download and extract the archive on the analysis computer, then run DroidSec locally. The original source files are read-only; reports are written to a separate output directory.

For a Unisoc/Spreadtrum PAC file:

```bash
droidsec analyze-local ./R2406_firmware.pac --out ./reports/polytron-r2406
```

For a firmware tree that you have already extracted:

```bash
droidsec analyze-local ./R2406_extracted --out ./reports/polytron-r2406
```

Optional evidence-only GLM assessment and offline CVE data:

```bash
droidsec analyze-local ./R2406_firmware.pac \
  --ai --cve-json ./nvd.json --out ./reports/polytron-r2406
```

The command creates `report.json` and `report.md`, containing file sizes and SHA-256 hashes, filename-based partition hints, device fingerprint evidence, ADB/MTP static review, SELinux source-policy triage, and optional CVE/bulletin/AI results. For a PAC input, it also parses the PAC table and extracts payloads into the report directory's `pac_extracted/` folder. It refuses to overwrite an existing PAC extraction folder.

### Handling the R2406 .7z sample

The `.7z` container is intentionally extracted outside DroidSec using 7-Zip (or p7zip); DroidSec's safe archive extractor currently supports ZIP/TAR, not 7z. In WSL2 Ubuntu:

```bash
sudo apt update
sudo apt install -y p7zip-full
7z x R2406_SC7731_EMMC_4.4.2_1300C_V1.0.8_20150918_20160901+PAC+File.7z -oR2406_extracted
find R2406_extracted -type f -iname '*.pac' -print
```

Then pass the discovered PAC path to `analyze-local`. If the PAC parser rejects the file, preserve the original and send the error plus the PAC header metadata; do not force extraction. A PAC revision mismatch is a parser-compatibility issue, not proof the firmware is corrupt.

**Important boundaries:** the workflow does not mount raw filesystems or automatically unpack ext4/EROFS/squashfs partition images. It inventories and hashes those images, and scans any already-extracted text/configuration. PAC parsing is revision-dependent. Compare extraction results with a second trusted PAC parser before considering the partition extraction validated. No firmware binaries are uploaded by this command.
