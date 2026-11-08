import sys
from oem_research.cli import main

def test_cli_import_and_vendors_command(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["droidsec", "vendors"])
    main()
    assert "Unisoc" in capsys.readouterr().out
