"""
In-app updater. Runs `git fetch` to compare HEAD with origin and `git pull
--ff-only` to apply, all wrapped to never block the asyncio event loop.

Operator intent: a one-click 'pull latest' from the Config tab so MSP
operators don't need terminal access to update. We deliberately do not
restart the process from inside it — uvicorn + venv on Windows make
process-respawn fragile. Instead we tell the operator to restart the
launcher; the launcher already reinstalls deps from requirements.txt
on each run, so 'apply update + restart' is fully automatic.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

log = logging.getLogger("dws.updater")


def _git_available() -> bool:
    return shutil.which("git") is not None


def _git_sync(*args: str, timeout: float = 60.0) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()


async def _git(*args: str, timeout: float = 60.0) -> tuple[int, str, str]:
    return await asyncio.to_thread(_git_sync, *args, timeout=timeout)


def _is_repo_sync() -> bool:
    if not _git_available():
        return False
    try:
        rc, _, _ = _git_sync("rev-parse", "--is-inside-work-tree")
        return rc == 0
    except Exception:
        return False


async def status() -> dict:
    if not _git_available():
        return {"is_repo": False, "error": "git is not installed on this host"}
    if not await asyncio.to_thread(_is_repo_sync):
        return {"is_repo": False, "error": "not a git checkout"}

    rc, branch, _ = await _git("rev-parse", "--abbrev-ref", "HEAD")
    if rc != 0 or not branch:
        return {"is_repo": True, "error": "could not determine current branch"}

    _, head_sha, _ = await _git("rev-parse", "--short", "HEAD")
    _, head_full, _ = await _git("rev-parse", "HEAD")
    _, head_subject, _ = await _git("log", "-1", "--pretty=%s", "HEAD")

    fetch_rc, _, fetch_err = await _git("fetch", "--quiet", "origin", branch, timeout=45)
    fetched = fetch_rc == 0

    rc, upstream_sha, _ = await _git("rev-parse", "--short", f"origin/{branch}")
    has_upstream = rc == 0 and upstream_sha

    if has_upstream:
        rc, ahead_count, _ = await _git("rev-list", "--count", f"origin/{branch}..HEAD")
        ahead = int(ahead_count) if rc == 0 and ahead_count.isdigit() else 0
        rc, behind_count, _ = await _git("rev-list", "--count", f"HEAD..origin/{branch}")
        behind = int(behind_count) if rc == 0 and behind_count.isdigit() else 0
    else:
        ahead = behind = 0

    rc, _, _ = await _git("diff", "--quiet")
    rc2, _, _ = await _git("diff", "--cached", "--quiet")
    dirty = rc != 0 or rc2 != 0

    return {
        "is_repo": True,
        "branch": branch,
        "head_sha": head_sha,
        "head_full": head_full,
        "head_subject": head_subject,
        "upstream_sha": upstream_sha if has_upstream else None,
        "ahead": ahead,
        "behind": behind,
        "dirty": dirty,
        "fetched": fetched,
        "fetch_error": fetch_err if not fetched else None,
        "update_available": has_upstream and behind > 0 and not dirty,
    }


async def apply_update() -> dict:
    if not _git_available():
        return {"ok": False, "error": "git is not installed on this host"}
    if not await asyncio.to_thread(_is_repo_sync):
        return {"ok": False, "error": "not a git checkout"}

    rc, branch, _ = await _git("rev-parse", "--abbrev-ref", "HEAD")
    if rc != 0 or not branch:
        return {"ok": False, "error": "could not determine current branch"}

    rc, _, _ = await _git("diff", "--quiet")
    rc2, _, _ = await _git("diff", "--cached", "--quiet")
    if rc != 0 or rc2 != 0:
        return {"ok": False, "error": "local uncommitted changes; commit/stash before updating"}

    fetch_rc, fout, ferr = await _git("fetch", "origin", branch, timeout=60)
    if fetch_rc != 0:
        return {"ok": False, "error": f"fetch failed: {(ferr or fout) or 'unknown error'}"}

    rc, before_sha, _ = await _git("rev-parse", "--short", "HEAD")

    merge_rc, mout, merr = await _git("merge", "--ff-only", f"origin/{branch}", timeout=60)
    if merge_rc != 0:
        return {"ok": False, "error": f"fast-forward failed: {(merr or mout) or 'history diverged'}"}

    rc, after_sha, _ = await _git("rev-parse", "--short", "HEAD")
    rc, log_out, _ = await _git("log", f"{before_sha}..{after_sha}",
                                 "--pretty=format:%h %s", "--no-merges")
    return {
        "ok": True,
        "before_sha": before_sha,
        "after_sha": after_sha,
        "summary": log_out.splitlines() if log_out else [],
        "restart_needed": before_sha != after_sha,
    }
