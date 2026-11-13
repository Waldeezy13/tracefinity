import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api import routes
from app.config import Settings, ensure_user_dirs
from app.models.schemas import BinConfig, BinModel, PlacedTool, Point
from app.services.bin_export import BinExportError, export_bin


def test_export_copies_available_files_without_deleting_remote_files(tmp_path, monkeypatch):
    for suffix, content in [(".stl", b"full"), (".3mf", b"3mf"),
                            ("_parts.zip", b"zip"), ("_insert.stl", b"insert")]:
        (tmp_path / f"id{suffix}").write_bytes(content)
    calls = []
    remote = {"drive:parent/Tool-Box/notes.txt": b"unrelated"}

    def run(args, **kwargs):
        assert args[:3] == ["rclone", "copyto", "--"]
        assert 0 < kwargs["timeout"] <= 90
        calls.append(args[-1])
        remote[args[-1]] = Path(args[-2]).read_bytes()
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    export_bin("drive:parent", "user/one", "../Tool Box", "id", tmp_path)
    assert len(calls) == 4
    assert all(path.startswith("drive:parent/Tool-Box/Tool-Box-") for path in calls)
    assert [remote[path] for path in calls] == [b"full", b"3mf", b"zip", b"insert"]
    assert [path.rsplit(".", 1)[-1] for path in calls] == ["stl", "3mf", "zip", "stl"]
    assert len(calls[0].removesuffix(".stl").rsplit("-", 1)[-1]) == 16
    first_paths = calls[:]
    (tmp_path / "id.3mf").unlink()
    (tmp_path / "id_parts.zip").unlink()
    (tmp_path / "id_insert.stl").unlink()
    export_bin("drive:parent", "user/one", "../Tool Box", "id", tmp_path)
    assert calls[4:] == [first_paths[0]]
    assert all(path in remote for path in first_paths)
    assert remote["drive:parent/Tool-Box/notes.txt"] == b"unrelated"
    export_bin("drive:parent", "user/two", "../Tool Box", "id", tmp_path)
    assert calls[-1] != first_paths[0]
    (tmp_path / "other.stl").write_bytes(b"other")
    export_bin("drive:parent", "user/one", "../Tool Box", "other", tmp_path)
    assert calls[-1] not in first_paths


def test_export_reports_process_and_missing_file_errors(tmp_path, monkeypatch):
    (tmp_path / "id.stl").write_bytes(b"stl")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=7))
    with pytest.raises(BinExportError, match="status 7"):
        export_bin("drive:", "user", "bin", "id", tmp_path)
    (tmp_path / "id.stl").unlink()
    with pytest.raises(BinExportError):
        export_bin("drive:", "user", "bin", "id", tmp_path)


def test_remote_setting_requires_named_remote():
    assert Settings(_env_file=None, rclone_export_remote="drive:exports").rclone_export_remote == "drive:exports"
    with pytest.raises(ValidationError):
        Settings(_env_file=None, rclone_export_remote="--bad")


@pytest.mark.parametrize("error", [FileNotFoundError(2, "not found"), subprocess.TimeoutExpired("rclone", 90)])
def test_export_reports_unavailable_or_timed_out_rclone(tmp_path, monkeypatch, error):
    (tmp_path / "id.stl").write_bytes(b"stl")

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(BinExportError):
        export_bin("drive:", "user", "bin", "id", tmp_path)


def _setup_bin(tmp_path, monkeypatch, remote):
    monkeypatch.setattr(routes.settings, "storage_path", tmp_path)
    monkeypatch.setattr(routes.settings, "rclone_export_remote", remote)
    monkeypatch.setattr(routes, "_store_cache", {})
    monkeypatch.setattr(routes, "_stl_generation_semaphore", None)
    ensure_user_dirs(tmp_path / "default")
    _, _, bins = routes.get_stores("default")
    bins.set("id", BinModel(id="id", name="Tool Box", bin_config=BinConfig(), placed_tools=[
        PlacedTool(id="p", tool_id="t", name="tool", points=[
            Point(x=0, y=0), Point(x=10, y=0), Point(x=10, y=10), Point(x=0, y=10)
        ])
    ]))
    generated = []

    class Generator:
        def generate_bin(self, scaled, request, output, threemf):
            generated.append(output)
            Path(output).write_bytes(b"geometry")
            return object(), None

        def export_split_parts(self, *args):
            return []

    monkeypatch.setattr(routes, "stl_generator", Generator())
    return generated, bins


def test_failed_export_retries_on_cache_hit_without_losing_local_output(tmp_path, monkeypatch):
    generated, bins = _setup_bin(tmp_path, monkeypatch, "drive:exports")
    calls = []

    def export(*args):
        calls.append(args)
        if len(calls) == 1:
            raise BinExportError("rclone exited with status 1")

    monkeypatch.setattr(routes, "export_bin", export)
    with pytest.raises(HTTPException) as failure:
        routes.generate_bin_stl(None, "id", "default")
    assert failure.value.status_code == 502
    assert (tmp_path / "default/outputs/id.stl").read_bytes() == b"geometry"
    assert bins.get("id").stl_path
    response = routes.generate_bin_stl(None, "id", "default")
    assert response.stl_url.endswith("/id.stl")
    assert len(generated) == 1
    assert len(calls) == 2


def test_disabled_export_never_calls_rclone(tmp_path, monkeypatch):
    _setup_bin(tmp_path, monkeypatch, None)
    monkeypatch.setattr(routes, "export_bin", lambda *args: pytest.fail("export disabled"))
    assert routes.generate_bin_stl(None, "id", "default").stl_url.endswith("/id.stl")


def test_export_holds_generation_lock(tmp_path, monkeypatch):
    _setup_bin(tmp_path, monkeypatch, "drive:")
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def export(*args):
        calls.append(args)
        if len(calls) == 1:
            entered.set()
            assert release.wait(5)

    monkeypatch.setattr(routes, "export_bin", export)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(routes.generate_bin_stl, None, "id", "default")
        assert entered.wait(5)
        second = pool.submit(routes.generate_bin_stl, None, "id", "default")
        assert not second.done()
        release.set()
        first.result(timeout=5)
        second.result(timeout=5)
    assert len(calls) == 2
