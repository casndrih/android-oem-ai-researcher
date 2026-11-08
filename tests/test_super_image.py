from pathlib import Path
import pytest
from oem_research.super_image import unpack_super

def test_super_unpack_requires_existing_image(tmp_path):
    with pytest.raises(FileNotFoundError):
        unpack_super(tmp_path/"missing.img", tmp_path/"out")
