"""Tests for the in-app updater. We mock the subprocess git calls and the
GitHub HTTP layer so the suite runs in any environment, including ones
without a real git repo or network access."""

import gzip
import io
import tarfile
from unittest.mock import patch

import pytest

from backend import updater


def _fake_git(responses):
    """Build a side_effect that returns rc/stdout/stderr for each call in order
    based on the args the caller passed."""
    def side_effect(*args, **kwargs):
        # args == ("rev-parse", "HEAD") etc.
        for matcher, result in responses:
            if matcher == args:
                return result
        # Default: empty success
        return (0, "", "")
    return side_effect


# ── git mode ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_status_up_to_date(monkeypatch):
    monkeypatch.setattr(updater, "_git_available", lambda: True)
    monkeypatch.setattr(updater, "_is_repo_sync", lambda: True)

    side_effect = _fake_git([
        (("rev-parse", "--abbrev-ref", "HEAD"), (0, "main", "")),
        (("rev-parse", "--short", "HEAD"), (0, "abc123", "")),
        (("rev-parse", "HEAD"), (0, "abc123def456", "")),
        (("log", "-1", "--pretty=%s", "HEAD"), (0, "Latest commit subject", "")),
        (("fetch", "--quiet", "origin", "main"), (0, "", "")),
        (("rev-parse", "--short", "origin/main"), (0, "abc123", "")),
        (("rev-list", "--count", "origin/main..HEAD"), (0, "0", "")),
        (("rev-list", "--count", "HEAD..origin/main"), (0, "0", "")),
        (("diff", "--quiet"), (0, "", "")),
        (("diff", "--cached", "--quiet"), (0, "", "")),
    ])
    with patch("backend.updater._git_sync", side_effect=side_effect):
        out = await updater.status()

    assert out["is_repo"] is True
    assert out["available"] is True
    assert out["mode"] == "git"
    assert out["branch"] == "main"
    assert out["behind"] == 0
    assert out["update_available"] is False
    assert out["dirty"] is False
    assert out["head_subject"] == "Latest commit subject"


@pytest.mark.asyncio
async def test_status_behind_origin(monkeypatch):
    monkeypatch.setattr(updater, "_git_available", lambda: True)
    monkeypatch.setattr(updater, "_is_repo_sync", lambda: True)

    side_effect = _fake_git([
        (("rev-parse", "--abbrev-ref", "HEAD"), (0, "main", "")),
        (("rev-parse", "--short", "HEAD"), (0, "old111", "")),
        (("rev-parse", "HEAD"), (0, "old111aaa", "")),
        (("log", "-1", "--pretty=%s", "HEAD"), (0, "old commit", "")),
        (("fetch", "--quiet", "origin", "main"), (0, "", "")),
        (("rev-parse", "--short", "origin/main"), (0, "new222", "")),
        (("rev-list", "--count", "origin/main..HEAD"), (0, "0", "")),
        (("rev-list", "--count", "HEAD..origin/main"), (0, "3", "")),
        (("diff", "--quiet"), (0, "", "")),
        (("diff", "--cached", "--quiet"), (0, "", "")),
    ])
    with patch("backend.updater._git_sync", side_effect=side_effect):
        out = await updater.status()

    assert out["mode"] == "git"
    assert out["behind"] == 3
    assert out["update_available"] is True


@pytest.mark.asyncio
async def test_status_dirty_blocks_update(monkeypatch):
    monkeypatch.setattr(updater, "_git_available", lambda: True)
    monkeypatch.setattr(updater, "_is_repo_sync", lambda: True)

    side_effect = _fake_git([
        (("rev-parse", "--abbrev-ref", "HEAD"), (0, "main", "")),
        (("rev-parse", "--short", "HEAD"), (0, "old111", "")),
        (("rev-parse", "HEAD"), (0, "old111aaa", "")),
        (("log", "-1", "--pretty=%s", "HEAD"), (0, "x", "")),
        (("fetch", "--quiet", "origin", "main"), (0, "", "")),
        (("rev-parse", "--short", "origin/main"), (0, "new222", "")),
        (("rev-list", "--count", "origin/main..HEAD"), (0, "0", "")),
        (("rev-list", "--count", "HEAD..origin/main"), (0, "1", "")),
        (("diff", "--quiet"), (1, "", "")),  # dirty working tree
        (("diff", "--cached", "--quiet"), (0, "", "")),
    ])
    with patch("backend.updater._git_sync", side_effect=side_effect):
        out = await updater.status()

    assert out["dirty"] is True
    assert out["update_available"] is False  # dirty blocks update


@pytest.mark.asyncio
async def test_apply_refuses_when_dirty(monkeypatch):
    monkeypatch.setattr(updater, "_git_available", lambda: True)
    monkeypatch.setattr(updater, "_is_repo_sync", lambda: True)

    side_effect = _fake_git([
        (("rev-parse", "--abbrev-ref", "HEAD"), (0, "main", "")),
        (("diff", "--quiet"), (1, "", "")),  # dirty
        (("diff", "--cached", "--quiet"), (0, "", "")),
    ])
    with patch("backend.updater._git_sync", side_effect=side_effect):
        out = await updater.apply_update()

    assert out["ok"] is False
    assert "uncommitted" in out["error"]


@pytest.mark.asyncio
async def test_apply_success(monkeypatch):
    monkeypatch.setattr(updater, "_git_available", lambda: True)
    monkeypatch.setattr(updater, "_is_repo_sync", lambda: True)

    side_effect = _fake_git([
        (("rev-parse", "--abbrev-ref", "HEAD"), (0, "main", "")),
        (("diff", "--quiet"), (0, "", "")),
        (("diff", "--cached", "--quiet"), (0, "", "")),
        (("fetch", "origin", "main"), (0, "", "")),
        (("rev-parse", "--short", "HEAD"), (0, "before1", "")),
        (("merge", "--ff-only", "origin/main"), (0, "Updating", "")),
        (("log", "before1..", "--pretty=format:%h %s", "--no-merges"),
         (0, "newsha1 commit one\nnewsha2 commit two", "")),
    ])
    # rev-parse --short HEAD called twice; need varied returns
    call_state = {"head_calls": 0}

    def mixed_side_effect(*args, **kwargs):
        if args == ("rev-parse", "--short", "HEAD"):
            call_state["head_calls"] += 1
            if call_state["head_calls"] == 1:
                return (0, "before1", "")
            return (0, "after2", "")
        return side_effect(*args, **kwargs)

    with patch("backend.updater._git_sync", side_effect=mixed_side_effect):
        out = await updater.apply_update()

    assert out["ok"] is True
    assert out["before_sha"] == "before1"
    assert out["after_sha"] == "after2"
    assert out["restart_needed"] is True


@pytest.mark.asyncio
async def test_apply_fetch_failure(monkeypatch):
    monkeypatch.setattr(updater, "_git_available", lambda: True)
    monkeypatch.setattr(updater, "_is_repo_sync", lambda: True)

    side_effect = _fake_git([
        (("rev-parse", "--abbrev-ref", "HEAD"), (0, "main", "")),
        (("diff", "--quiet"), (0, "", "")),
        (("diff", "--cached", "--quiet"), (0, "", "")),
        (("fetch", "origin", "main"), (1, "", "Could not resolve hostname")),
    ])
    with patch("backend.updater._git_sync", side_effect=side_effect):
        out = await updater.apply_update()

    assert out["ok"] is False
    assert "fetch failed" in out["error"]
    assert "Could not resolve hostname" in out["error"]


# ── tarball mode (no .git) ───────────────────────────────────────────────────

async def _async_return(value):
    return value


def _patch_tarball_env(monkeypatch, tmp_path):
    """Redirect ROOT and the installed-sha file into tmp_path so tarball-mode
    apply doesn't touch the real working tree."""
    monkeypatch.setattr(updater, "ROOT", tmp_path)
    monkeypatch.setattr(updater, "INSTALLED_SHA_FILE",
                        tmp_path / "data" / "installed_sha.txt")
    monkeypatch.setattr(updater, "_is_repo_sync", lambda: False)


@pytest.mark.asyncio
async def test_tarball_status_first_run(monkeypatch, tmp_path):
    """No installed SHA recorded yet → offer the apply so the SHA can be pinned."""
    _patch_tarball_env(monkeypatch, tmp_path)

    async def fake_latest(branch):
        return {"sha": "a" * 40, "short": "aaaaaaa", "subject": "first commit"}
    monkeypatch.setattr(updater, "_fetch_latest_commit", fake_latest)

    out = await updater.status()
    assert out["available"] is True
    assert out["is_repo"] is False
    assert out["mode"] == "tarball"
    assert out["head_sha"] is None
    assert out["upstream_sha"] == "aaaaaaa"
    assert out["update_available"] is True


@pytest.mark.asyncio
async def test_tarball_status_up_to_date(monkeypatch, tmp_path):
    _patch_tarball_env(monkeypatch, tmp_path)
    sha = "b" * 40
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "installed_sha.txt").write_text(sha + "\n")

    async def fake_latest(branch):
        return {"sha": sha, "short": sha[:7], "subject": "current tip"}
    monkeypatch.setattr(updater, "_fetch_latest_commit", fake_latest)

    out = await updater.status()
    assert out["mode"] == "tarball"
    assert out["update_available"] is False
    assert out["behind"] == 0
    assert out["head_sha"] == sha[:7]


@pytest.mark.asyncio
async def test_tarball_status_update_available(monkeypatch, tmp_path):
    _patch_tarball_env(monkeypatch, tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "installed_sha.txt").write_text("c" * 40 + "\n")

    async def fake_latest(branch):
        return {"sha": "d" * 40, "short": "ddddddd", "subject": "newer commit"}
    monkeypatch.setattr(updater, "_fetch_latest_commit", fake_latest)

    out = await updater.status()
    assert out["update_available"] is True
    assert out["upstream_sha"] == "ddddddd"
    assert out["upstream_subject"] == "newer commit"


@pytest.mark.asyncio
async def test_tarball_status_api_failure(monkeypatch, tmp_path):
    _patch_tarball_env(monkeypatch, tmp_path)

    async def boom(branch):
        raise RuntimeError("network down")
    monkeypatch.setattr(updater, "_fetch_latest_commit", boom)

    out = await updater.status()
    assert out["available"] is True
    assert out["fetched"] is False
    assert "network down" in out["fetch_error"]
    assert out["update_available"] is False


@pytest.mark.asyncio
async def test_tarball_apply_already_latest(monkeypatch, tmp_path):
    _patch_tarball_env(monkeypatch, tmp_path)
    sha = "e" * 40
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "installed_sha.txt").write_text(sha + "\n")

    async def fake_latest(branch):
        return {"sha": sha, "short": sha[:7], "subject": "x"}
    monkeypatch.setattr(updater, "_fetch_latest_commit", fake_latest)

    out = await updater.apply_update()
    assert out["ok"] is False
    assert "already at latest" in out["error"]


def _make_tarball(top: str, files: dict[str, bytes]) -> bytes:
    """Build an in-memory tar.gz mimicking GitHub's archive layout."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tf:
        # top-level dir entry
        info = tarfile.TarInfo(name=top)
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        tf.addfile(info)
        for rel, content in files.items():
            data = content
            info = tarfile.TarInfo(name=f"{top}/{rel}")
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return raw.getvalue()


@pytest.mark.asyncio
async def test_tarball_apply_overlays_files_and_pins_sha(monkeypatch, tmp_path):
    _patch_tarball_env(monkeypatch, tmp_path)
    # Pre-existing operator data that must be preserved
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "scanner.db").write_bytes(b"do-not-touch")
    (tmp_path / "data" / "admin_token.txt").write_text("secret")
    # Pre-existing source file that the update will overwrite
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "main.py").write_text("# old version\n")

    sha = "f" * 40
    tar = _make_tarball(
        top=f"{updater.UPSTREAM_OWNER}-{updater.UPSTREAM_REPO}-fffffff",
        files={
            "backend/main.py": b"# new version\n",
            "backend/new_module.py": b"NEW = True\n",
            "data/should_be_skipped.txt": b"upstream tried to ship this",
        },
    )

    async def fake_latest(branch):
        return {"sha": sha, "short": sha[:7], "subject": "shipped new module"}

    async def fake_download(s):
        assert s == sha
        return tar

    monkeypatch.setattr(updater, "_fetch_latest_commit", fake_latest)
    monkeypatch.setattr(updater, "_download_tarball", fake_download)

    out = await updater.apply_update()
    assert out["ok"] is True
    assert out["after_sha"] == sha[:7]
    assert out["restart_needed"] is True

    # Source files updated
    assert (tmp_path / "backend" / "main.py").read_text() == "# new version\n"
    assert (tmp_path / "backend" / "new_module.py").read_text() == "NEW = True\n"
    # Operator data untouched
    assert (tmp_path / "data" / "scanner.db").read_bytes() == b"do-not-touch"
    assert (tmp_path / "data" / "admin_token.txt").read_text() == "secret"
    # Tarball entry under data/ was rejected by the preservation guard
    assert not (tmp_path / "data" / "should_be_skipped.txt").exists()
    # SHA pinned
    assert (tmp_path / "data" / "installed_sha.txt").read_text().strip() == sha


def test_is_preserved_blocks_data_and_venvs():
    assert updater._is_preserved("data/scanner.db")
    assert updater._is_preserved("data/admin_token.txt")
    assert updater._is_preserved("data/installed_sha.txt")
    assert updater._is_preserved("backend/.venv/lib/python3.11/site-packages/x.py")
    assert updater._is_preserved(".venv/bin/activate")
    assert updater._is_preserved(".git/HEAD")
    assert updater._is_preserved("backend/__pycache__/main.cpython-311.pyc")
    assert updater._is_preserved("backend/main.pyc")
    assert updater._is_preserved("anything.db-wal")
    assert not updater._is_preserved("backend/main.py")
    assert not updater._is_preserved("frontend/static/js/app.js")
    assert not updater._is_preserved("README.md")


def test_extract_rejects_path_traversal(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "ROOT", tmp_path)
    # Tarball with an entry escaping the top-level dir
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tf:
        top = "evil-top"
        info = tarfile.TarInfo(name=top)
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
        bad = tarfile.TarInfo(name=f"{top}/../../escaped.txt")
        payload = b"pwned"
        bad.size = len(payload)
        tf.addfile(bad, io.BytesIO(payload))

    updater._extract_tarball_over_root(raw.getvalue())
    # Nothing should have been written outside tmp_path
    assert not (tmp_path.parent / "escaped.txt").exists()


# ── HTTP layer ────────────────────────────────────────────────────────────────

def test_status_endpoint_requires_auth(anon_client):
    r = anon_client.get("/api/update/status")
    assert r.status_code == 401


def test_apply_endpoint_requires_auth(anon_client):
    r = anon_client.post("/api/update/apply")
    assert r.status_code == 401


def test_status_endpoint_works(client, monkeypatch):
    async def fake_status():
        return {"is_repo": False, "available": True, "mode": "tarball",
                "branch": "main", "head_sha": "aaaaaaa", "upstream_sha": "bbbbbbb",
                "update_available": True, "behind": 1, "fetched": True}
    monkeypatch.setattr(updater, "status", fake_status)
    r = client.get("/api/update/status")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "tarball"
    assert body["update_available"] is True
