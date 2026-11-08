import pytest
from oem_research.approval import authorize, ApprovalRequired

def test_static_is_allowed():
    assert authorize("static-read")=="authorized-read-only"

def test_dynamic_requires_approval():
    with pytest.raises(ApprovalRequired): authorize("dynamic-test")

def test_flash_blocked_even_if_approved():
    with pytest.raises(PermissionError): authorize("flash",approved=True)
