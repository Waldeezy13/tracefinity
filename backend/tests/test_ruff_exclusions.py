"""Exercise lint discovery without relying on Git's ignored-file metadata."""

import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("ruff") is None, reason="Ruff is not installed")
def test_ruff_excludes_venv_but_checks_application_without_git(tmp_path):
    root = Path(__file__).resolve().parents[2]
    shutil.copy(root / "pyproject.toml", tmp_path / "pyproject.toml")
    app = tmp_path / "backend" / "app" / "module.py"
    dependency = tmp_path / "backend" / "venv" / "lib" / "python3.12" / "site-packages" / "dependency.py"
    app.parent.mkdir(parents=True)
    dependency.parent.mkdir(parents=True)
    app.write_text("import os\n")
    dependency.write_text("import sys\n")

    def lint():
        return subprocess.run(
            ["ruff", "check", "backend/", "--no-cache"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )

    result = lint()
    assert result.returncode == 1
    assert "app/module.py" in result.stdout
    assert "site-packages" not in result.stdout + result.stderr

    app.write_text("value = 1\n")
    result = lint()
    assert result.returncode == 0, result.stdout + result.stderr
