from oem_research.detect import identify

def test_boot_magic(tmp_path):
    p=tmp_path/"image.bin"; p.write_bytes(b"ANDROID!"+b"\0"*32)
    assert "android-boot-image" in identify(p)

def test_odin_extension(tmp_path):
    p=tmp_path/"AP_test.tar.md5"; p.write_bytes(b"")
    assert "samsung-odin-tar-candidate" in identify(p)
