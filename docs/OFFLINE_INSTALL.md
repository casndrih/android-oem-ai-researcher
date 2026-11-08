# Offline / zero-third-party-runtime-dependency mode

DroidSec's core analyzers use only the Python 3.10+ standard library. No pip
install, virtual environment, internet access, or third-party Python runtime
package is required to run the source checkout.

## Run directly after clone or ZIP download

Linux / WSL2:

    python3 droidsec.py vendors
    python3 droidsec.py analyze-local ./firmware_tree --out ./reports/sample

Windows PowerShell:

    py -3 droidsec.py vendors
    py -3 droidsec.py analyze-local .\firmware_tree --out .\reports\sample

Windows Command Prompt can use:

    droidsec.bat vendors

The `droidsec` shell launcher is also provided for Linux/WSL2. The source
checkout itself is the application; direct launch adds `src/` to Python's
module search path and does not install packages.

## Python dependencies

- Runtime Python packages: **none** (standard library only).
- GLM/OpenAI-compatible API: uses `urllib` from the standard library; the
  optional `openai` SDK is no longer required.
- Tests: `pytest` is a development-only dependency. GitHub Actions installs
  it in CI; end users do not need it to run DroidSec.
- Packaging with `pip install -e .` still uses the Python packaging build
  backend (setuptools/wheel). That backend is not needed for direct launch.

## Optional native / OS tools

Some specialized operations invoke host utilities that cannot safely or
portably be embedded as universal Python packages:

- `7z` / `p7zip`: external extraction of .7z archives.
- `lpunpack`: optional dynamic-super partition extraction.
- SETools (`seinfo`, `sesearch`): optional compiled SELinux policy queries.

These are optional, platform-specific tools. DroidSec reports when an optional
tool is unavailable; the core analysis and parsers remain usable without them.
Do not execute vendor programmers or firmware binaries.

## Why there is no giant vendor/ directory

The core has no third-party runtime Python dependencies, so copying hundreds
of megabytes of wheels into the repository would add platform-specific,
hard-to-audit supply-chain code without making the core more functional.
Python wheels for Windows, Linux, ARM and different Python versions are not
interchangeable. This repository therefore ships its own application source
and avoids requiring pip for normal execution. Optional OS tools remain
separately installed and explicitly documented.
