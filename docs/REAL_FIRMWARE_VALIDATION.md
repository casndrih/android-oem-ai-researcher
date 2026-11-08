# Real firmware validation plan

This project currently has synthetic regression fixtures. They test parser behaviour and safety checks; they are not evidence of compatibility with a real OEM release.

## Candidate public research sources

The following sources are useful for locating format documentation or a candidate test package. They are not bundled in this repository, and their presence does not grant redistribution rights.

| Format | Candidate source | What it can validate | Current status |
|---|---|---|---|
| Unisoc PAC | [Cubot KingKong ES 3 support firmware reference](https://github.com/KiMiGuel/Root-Guide-Cubot-KingKong-ES-3---Unisoc-T615-ums9230-) | A vendor-support PAC is described as approximately 3 GB; useful only if obtained from the manufacturer's support channel and its terms permit research | Not downloaded; no verified checksum or binary |
| Unisoc PAC tooling | [DiegoPtit/unisoc_tools](https://github.com/DiegoPtit/unisoc_tools) and [bismoy-bot/PAC-Extractor](https://github.com/bismoy-bot/PAC-Extractor) | Independent format/tooling cross-checks | Source-code references only; no confirmed firmware fixture |
| MediaTek scatter | [TCL FOTA tool](https://github.com/vehoelite/tcl-fota-tool) | Documents a vendor-server workflow and scatter/partition outputs for TCL-family devices | No firmware package mirrored here; use only packages obtained under applicable vendor terms |
| Qualcomm QFIL | [NHellFire/android-qfil-unsparse](https://github.com/NHellFire/android-qfil-unsparse) | Independent QFIL sparse-image handling; README reports testing against Lenovo Tab4 8 Plus firmware | No binary sample confirmed in repository |
| Qualcomm package metadata | [Qualcomm qcom-image-loader examples](https://github.com/qualcomm/qcom-image-loader/blob/main/doc/CliCommandList.md) | Reference for rawprogram/patch XML workflows | Documentation only; not a firmware package |

## Why binaries are not committed yet

- The GitHub integration available for this repository writes UTF-8 text files. It does not provide a supported binary Git blob upload path in this workflow.
- The public sources found so far either contain parser/tool source code and documentation, or point to large vendor firmware downloads rather than small, clearly redistributable test artifacts.
- Firmware packages may contain copyrighted vendor software, device-specific authentication material, radio/modem firmware, or security-sensitive components. A public download URL is not a redistribution licence.
- Do not put vendor DA/auth files, device-unique NV data, calibration data, user data, or proprietary full images in this repository.

## Reproducible real-sample procedure

When you have a package that you are authorised to analyse:

1. Keep the original archive outside the Git repository, in a local research samples directory.
2. Record the exact source URL, vendor/model, build identifier, acquisition date, package size, and SHA-256.
3. Preserve the original read-only and work on a copy.
4. Run the relevant read-only parser/extractor and save the JSON/Markdown report.
5. Cross-check partition names, offsets, sizes, and hashes against an independent tool or vendor manifest.
6. Commit only the small metadata manifest, test report, and any non-proprietary minimal fixture that the licence permits. Keep the actual firmware local or in an appropriately licensed private artifact store.

Example hash commands:

```powershell
Get-FileHash .\firmware-package.zip -Algorithm SHA256
```

```bash
sha256sum firmware-package.zip
```

## Validation acceptance criteria

A real package is considered validated only when all of the following are recorded:

- Exact package identity and source provenance.
- SHA-256 of the untouched original package.
- Parser output with no unexplained structural errors.
- Extracted file hashes and sizes.
- Independent comparison of partition inventory and metadata.
- Explicit list of unsupported/skipped records and codecs.

Synthetic fixtures remain useful CI regression tests, but must never be labelled as real firmware validation.
