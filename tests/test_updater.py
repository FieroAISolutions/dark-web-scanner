"""Tests for the in-app updater. We mock the subprocess git calls so the
suite runs in any environment, including ones without a real git repo."""

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


@pytest.mark.asyncio
async def test_status_when_not_a_repo(monkeypatch):
    monkeypatch.setattr(updater, "_git_available", lambda: True)
    monkeypatch.setattr(updater, "_is_repo_sync", lambda: False)
    out = await updater.status()
    assert out == {"is_repo": False, "error": "not a git checkout"}


@pytest.mark.asyncio
async def test_status_no_git_installed(monkeypatch):
    monkeypatch.setattr(updater, "_git_available", lambda: False)
    out = await updater.status()
    assert out["is_repo"] is False
    assert "git is not installed" in out["error"]


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


# ── HTTP layer ────────────────────────────────────────────────────────────────

def test_status_endpoint_requires_auth(anon_client):
    r = anon_client.get("/api/update/status")
    assert r.status_code == 401


def test_apply_endpoint_requires_auth(anon_client):
    r = anon_client.post("/api/update/apply")
    assert r.status_code == 401


def test_status_endpoint_works(client, monkeypatch):
    async def fake_status():
        return {"is_repo": False, "error": "not a git checkout"}
    monkeypatch.setattr(updater, "status", fake_status)
    r = client.get("/api/update/status")
    assert r.status_code == 200
    assert r.json() == {"is_repo": False, "error": "not a git checkout"}
