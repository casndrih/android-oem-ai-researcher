"""Run DroidSec AI directly from a cloned repository without pip installation."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from oem_research.cli import main

if __name__ == "__main__":
    main()
