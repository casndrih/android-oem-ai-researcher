from oem_research.archive import safe_name

def test_reject_traversal():
    assert not safe_name("../escape.txt")
    assert not safe_name("/absolute/path")

def test_accept_normal():
    assert safe_name("images/boot.img")
