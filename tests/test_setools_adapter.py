from pathlib import Path
from oem_research import setools_adapter

def test_compiled_policy_reports_missing_setools(tmp_path: Path, monkeypatch):
    policy=tmp_path/"sepolicy"; policy.write_bytes(b"fake-policy")
    monkeypatch.setattr(setools_adapter.shutil, "which", lambda name: None)
    result=setools_adapter.inspect_compiled_policy(policy)
    assert not result["available"]
    assert set(result["missing_tools"]) == {"seinfo", "sesearch"}

def test_compiled_policy_rejects_symlink(tmp_path: Path):
    target=tmp_path/"target"; target.write_bytes(b"policy")
    link=tmp_path/"link"; link.symlink_to(target)
    try:
        setools_adapter.inspect_compiled_policy(link)
    except ValueError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("symlink policy should be rejected")
