"""Tests for the in-app updater. We mock the subprocess git calls and the
GitHub HTTP layer so the suite runs in any environment, including ones
without a real git repo or network access."""

import asyncio
import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from backend import updater


def _fake_git(responses):
    """Build a side_effect that returns rc/stdout/stderr for each call in order
    based on the args the caller passed."""
    def side_effect(*args, **kwargs):
        for matcher, result in responses:
            if matcher == args:
                return result
        return (0, "", "")
    return side_effect


@pytest.fixture(autouse=True)
def _reset_updater_state(monkeypatch):
    """Each test starts with a fresh upstream-commit cache so prior tests
    can't leak fake responses."""
    monkeypatch.setattr(updater, "_latest_cache",
                        {"ts": 0.0, "branch": None, "value": None})
    yield


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
        (("diff", "--quiet"), (1, "", "")),
        (("diff", "--cached", "--quiet"), (0, "", "")),
    ])
    with patch("backend.updater._git_sync", side_effect=side_effect):
        out = await updater.status()

    assert out["dirty"] is True
    assert out["update_available"] is False


@pytest.mark.asyncio
async def test_apply_refuses_when_dirty(monkeypatch):
    monkeypatch.setattr(updater, "_git_available", lambda: True)
    monkeypatch.setattr(updater, "_is_repo_sync", lambda: True)

    side_effect = _fake_git([
        (("rev-parse", "--abbrev-ref", "HEAD"), (0, "main", "")),
        (("diff", "--quiet"), (1, "", "")),
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

def _patch_tarball_env(monkeypatch, tmp_path):
    """Redirect ROOT and the installed-sha file into tmp_path so tarball-mode
    apply doesn't touch the real working tree."""
    monkeypatch.setattr(updater, "ROOT", tmp_path)
    monkeypatch.setattr(updater, "INSTALLED_SHA_FILE",
                        tmp_path / "data" / "installed_sha.txt")
    monkeypatch.setattr(updater, "BACKUP_DIR", tmp_path / "data" / ".update_backup")
    monkeypatch.setattr(updater, "_is_repo_sync", lambda: False)


@pytest.mark.asyncio
async def test_tarball_status_first_run(monkeypatch, tmp_path):
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
async def test_tarball_status_uses_cache(monkeypatch, tmp_path):
    """A second status call within the cache TTL must not re-hit the API."""
    _patch_tarball_env(monkeypatch, tmp_path)
    calls = {"n": 0}

    async def fake_latest(branch):
        calls["n"] += 1
        return {"sha": "z" * 40, "short": "zzzzzzz", "subject": "cached"}
    monkeypatch.setattr(updater, "_fetch_latest_commit", fake_latest)

    await updater.status()
    await updater.status()
    await updater.status()
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_tarball_status_force_refresh_bypasses_cache(monkeypatch, tmp_path):
    _patch_tarball_env(monkeypatch, tmp_path)
    calls = {"n": 0}

    async def fake_latest(branch):
        calls["n"] += 1
        return {"sha": "z" * 40, "short": "zzzzzzz", "subject": "x"}
    monkeypatch.setattr(updater, "_fetch_latest_commit", fake_latest)

    await updater.status()
    await updater.status(force_refresh=True)
    assert calls["n"] == 2


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
    assert out["files_changed"] >= 2

    assert (tmp_path / "backend" / "main.py").read_text() == "# new version\n"
    assert (tmp_path / "backend" / "new_module.py").read_text() == "NEW = True\n"
    assert (tmp_path / "data" / "scanner.db").read_bytes() == b"do-not-touch"
    assert (tmp_path / "data" / "admin_token.txt").read_text() == "secret"
    assert not (tmp_path / "data" / "should_be_skipped.txt").exists()
    assert (tmp_path / "data" / "installed_sha.txt").read_text().strip() == sha


@pytest.mark.asyncio
async def test_tarball_apply_prunes_removed_files_in_tracked_dirs(monkeypatch, tmp_path):
    """Files that exist locally inside backend/, frontend/, tests/ but are
    absent upstream must be deleted (smart sync)."""
    _patch_tarball_env(monkeypatch, tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "installed_sha.txt").write_text("0" * 40 + "\n")

    # Local files: one will survive (still upstream), one will be pruned
    # (upstream removed), and a root-level custom file that must NOT be pruned
    # because it's outside _PRUNABLE_DIRS.
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "main.py").write_text("local main\n")
    (tmp_path / "backend" / "obsolete.py").write_text("removed upstream\n")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "old_template.html").write_text("dead\n")
    (tmp_path / "operator_notes.md").write_text("operator-managed\n")

    sha = "1" * 40
    tar = _make_tarball(
        top=f"{updater.UPSTREAM_OWNER}-{updater.UPSTREAM_REPO}-1111111",
        files={
            "backend/main.py": b"upstream main\n",
            # Note: backend/obsolete.py absent → must be pruned
            # Note: frontend/old_template.html absent → must be pruned
            "frontend/static/js/app.js": b"new app\n",
        },
    )

    async def fake_latest(branch):
        return {"sha": sha, "short": sha[:7], "subject": "cleanup"}

    async def fake_download(s):
        return tar

    monkeypatch.setattr(updater, "_fetch_latest_commit", fake_latest)
    monkeypatch.setattr(updater, "_download_tarball", fake_download)

    out = await updater.apply_update()
    assert out["ok"] is True
    assert out["files_removed"] == 2

    assert (tmp_path / "backend" / "main.py").read_text() == "upstream main\n"
    assert (tmp_path / "frontend" / "static" / "js" / "app.js").read_text() == "new app\n"
    assert not (tmp_path / "backend" / "obsolete.py").exists()
    assert not (tmp_path / "frontend" / "old_template.html").exists()
    # Root-level operator-managed file must be left alone.
    assert (tmp_path / "operator_notes.md").read_text() == "operator-managed\n"


@pytest.mark.asyncio
async def test_tarball_apply_rolls_back_on_failure(monkeypatch, tmp_path):
    """If overlay copy raises mid-apply, the snapshot must restore the
    pre-update state."""
    _patch_tarball_env(monkeypatch, tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "installed_sha.txt").write_text("0" * 40 + "\n")
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "main.py").write_text("ORIGINAL\n")
    (tmp_path / "backend" / "doomed.py").write_text("ORIGINAL doomed\n")

    sha = "2" * 40
    tar = _make_tarball(
        top=f"{updater.UPSTREAM_OWNER}-{updater.UPSTREAM_REPO}-2222222",
        files={
            "backend/main.py": b"NEW main\n",
            "backend/doomed.py": b"NEW doomed\n",
        },
    )

    async def fake_latest(branch):
        return {"sha": sha, "short": sha[:7], "subject": "x"}

    async def fake_download(s):
        return tar

    monkeypatch.setattr(updater, "_fetch_latest_commit", fake_latest)
    monkeypatch.setattr(updater, "_download_tarball", fake_download)

    real_copy = updater.shutil.copy2
    overlay_writes = {"n": 0}

    def flaky_copy2(src, dst, *a, **kw):
        # Snapshot writes go *to* BACKUP_DIR; restore writes come *from*
        # BACKUP_DIR. Both must succeed. Only overlay writes (root → root)
        # should be made to fail, on the second overlay copy.
        if str(dst).startswith(str(updater.BACKUP_DIR)) \
                or str(src).startswith(str(updater.BACKUP_DIR)):
            return real_copy(src, dst, *a, **kw)
        overlay_writes["n"] += 1
        if overlay_writes["n"] >= 2:
            raise OSError("simulated disk full")
        return real_copy(src, dst, *a, **kw)

    monkeypatch.setattr(updater.shutil, "copy2", flaky_copy2)

    out = await updater.apply_update()
    assert out["ok"] is False
    assert "rolled back" in out["error"]

    # Snapshot restored both originals; SHA file unchanged.
    contents = {
        (tmp_path / "backend" / "main.py").read_text(),
        (tmp_path / "backend" / "doomed.py").read_text(),
    }
    assert "ORIGINAL\n" in contents
    assert "ORIGINAL doomed\n" in contents
    assert (tmp_path / "data" / "installed_sha.txt").read_text().strip() == "0" * 40


@pytest.mark.asyncio
async def test_tarball_apply_rejects_sha_mismatch(monkeypatch, tmp_path):
    """A tarball whose top dir doesn't carry the expected short SHA is treated
    as corrupt and not applied."""
    _patch_tarball_env(monkeypatch, tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "installed_sha.txt").write_text("0" * 40 + "\n")
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "main.py").write_text("KEEP\n")

    sha = "3" * 40
    # Top dir has a wrong sha embedded
    tar = _make_tarball(
        top=f"{updater.UPSTREAM_OWNER}-{updater.UPSTREAM_REPO}-DEADBEEF",
        files={"backend/main.py": b"REPLACED\n"},
    )

    async def fake_latest(branch):
        return {"sha": sha, "short": sha[:7], "subject": "x"}

    async def fake_download(s):
        return tar

    monkeypatch.setattr(updater, "_fetch_latest_commit", fake_latest)
    monkeypatch.setattr(updater, "_download_tarball", fake_download)

    out = await updater.apply_update()
    assert out["ok"] is False
    assert "sha" in out["error"].lower()
    assert (tmp_path / "backend" / "main.py").read_text() == "KEEP\n"


@pytest.mark.asyncio
async def test_concurrent_apply_rejected(monkeypatch, tmp_path):
    _patch_tarball_env(monkeypatch, tmp_path)

    async with updater._apply_lock:
        out = await updater.apply_update()

    assert out["ok"] is False
    assert "already in progress" in out["error"]


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


def test_in_prunable_dir():
    assert updater._in_prunable_dir("backend/main.py")
    assert updater._in_prunable_dir("frontend/static/js/app.js")
    assert updater._in_prunable_dir("tests/test_x.py")
    assert not updater._in_prunable_dir("README.md")
    assert not updater._in_prunable_dir("run_mac_linux.sh")
    assert not updater._in_prunable_dir("operator_notes.md")


def test_extract_rejects_path_traversal(tmp_path):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tf:
        top = "evil-top-aaaaaaa"
        info = tarfile.TarInfo(name=top)
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
        bad = tarfile.TarInfo(name=f"{top}/../../escaped.txt")
        payload = b"pwned"
        bad.size = len(payload)
        tf.addfile(bad, io.BytesIO(payload))

    staging = tmp_path / "stage"
    updater._extract_tarball_to_staging(raw.getvalue(), staging, "a" * 40)
    assert not (tmp_path.parent / "escaped.txt").exists()
    assert not (tmp_path / "escaped.txt").exists()


def test_short_err_trims_verbose_messages():
    e = RuntimeError("a" * 500)
    assert len(updater._short_err(e)) <= 200
    assert "RuntimeError" in updater._short_err(e)


# ── auth: GitHub token plumbing ──────────────────────────────────────────────

def test_diagnose_404_without_token_suggests_setup(monkeypatch):
    monkeypatch.setattr(updater, "_get_github_token", lambda: "")
    hint = updater._diagnose_http_error(RuntimeError(
        "Client error '404 Not Found' for url 'https://api.github.com/...'"
    ))
    assert "private repo" in hint
    assert "GitHub token" in hint


def test_diagnose_404_with_token_does_not_suggest_setup(monkeypatch):
    monkeypatch.setattr(updater, "_get_github_token", lambda: "ghp_xxx")
    hint = updater._diagnose_http_error(RuntimeError("404"))
    assert "private repo" not in hint


def test_diagnose_401_suggests_token_scope(monkeypatch):
    monkeypatch.setattr(updater, "_get_github_token", lambda: "ghp_xxx")
    hint = updater._diagnose_http_error(RuntimeError(
        "Client error '401 Unauthorized' for url ..."
    ))
    assert "token rejected" in hint or "scope" in hint


def test_auth_headers_empty_without_token(monkeypatch):
    monkeypatch.setattr(updater, "_get_github_token", lambda: "")
    assert updater._auth_headers() == {}


def test_auth_headers_present_with_token(monkeypatch):
    monkeypatch.setattr(updater, "_get_github_token", lambda: "ghp_secret")
    assert updater._auth_headers() == {"Authorization": "Bearer ghp_secret"}


@pytest.mark.asyncio
async def test_fetch_latest_commit_sends_authorization_header(monkeypatch):
    """End-to-end: a token stored in config must reach the GitHub API as a
    Bearer header on the commits endpoint."""
    monkeypatch.setattr(updater, "_get_github_token", lambda: "ghp_unit_test")

    captured = {}

    class FakeResponse:
        def raise_for_status(self): pass
        def json(self):
            return {"sha": "a" * 40, "commit": {"message": "hello world"}}

    class FakeClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, headers=None):
            captured["url"] = url
            captured["headers"] = headers or {}
            return FakeResponse()

    monkeypatch.setattr(updater.httpx, "AsyncClient", FakeClient)
    out = await updater._fetch_latest_commit("main")
    assert out["sha"] == "a" * 40
    assert captured["headers"].get("Authorization") == "Bearer ghp_unit_test"
    assert "commits/main" in captured["url"]


@pytest.mark.asyncio
async def test_download_tarball_uses_api_endpoint_with_auth(monkeypatch):
    monkeypatch.setattr(updater, "_get_github_token", lambda: "ghp_unit_test")

    captured = {}

    class FakeResponse:
        content = b"fake tarball bytes"
        def raise_for_status(self): pass

    class FakeClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url, headers=None):
            captured["url"] = url
            captured["headers"] = headers or {}
            return FakeResponse()

    monkeypatch.setattr(updater.httpx, "AsyncClient", FakeClient)
    out = await updater._download_tarball("a" * 40)
    assert out == b"fake tarball bytes"
    assert "api.github.com" in captured["url"]
    assert "/tarball/" in captured["url"]
    assert captured["headers"].get("Authorization") == "Bearer ghp_unit_test"


@pytest.mark.asyncio
async def test_get_github_token_swallows_db_failure(monkeypatch):
    """If the DB read raises (e.g. very early boot), token lookup must fall
    back to empty string rather than crashing the updater."""
    def boom():
        raise RuntimeError("db not initialized")
    monkeypatch.setattr(updater.config_mod, "get_full", boom)
    assert updater._get_github_token() == ""


# ── HTTP layer ────────────────────────────────────────────────────────────────

def test_status_endpoint_requires_auth(anon_client):
    r = anon_client.get("/api/update/status")
    assert r.status_code == 401


def test_apply_endpoint_requires_auth(anon_client):
    r = anon_client.post("/api/update/apply")
    assert r.status_code == 401


def test_status_endpoint_works(client, monkeypatch):
    async def fake_status(*, force_refresh=False):
        return {"is_repo": False, "available": True, "mode": "tarball",
                "branch": "main", "head_sha": "aaaaaaa", "upstream_sha": "bbbbbbb",
                "update_available": True, "behind": 1, "fetched": True}
    monkeypatch.setattr(updater, "status", fake_status)
    r = client.get("/api/update/status")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "tarball"
    assert body["update_available"] is True


def test_status_endpoint_passes_refresh_param(client, monkeypatch):
    received = {}

    async def fake_status(*, force_refresh=False):
        received["force_refresh"] = force_refresh
        return {"is_repo": False, "available": True, "mode": "tarball"}

    monkeypatch.setattr(updater, "status", fake_status)
    client.get("/api/update/status?refresh=1")
    assert received["force_refresh"] is True
    client.get("/api/update/status")
    assert received["force_refresh"] is False
