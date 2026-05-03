"""
In-app updater. Two modes:

  * git mode — when the deployment is a git checkout, runs `git fetch` /
    `git pull --ff-only` to compare HEAD with origin and apply.
  * tarball mode — when no .git is present (e.g. ZIP install from GitHub),
    queries the GitHub REST API for the upstream branch tip and overlays the
    repo tarball onto the working tree. The currently-installed commit SHA is
    persisted to data/installed_sha.txt so subsequent checks know whether an
    update is available. Within the source dirs in `_PRUNABLE_DIRS`, files
    that exist locally but not upstream are removed (so deletions propagate);
    everything else is overlay-only. Each apply takes a snapshot of the files
    it is about to touch into data/.update_backup/ and rolls back on failure.

Operator intent: a one-click 'pull latest' from the Config tab so MSP
operators don't need terminal access (or even git installed) to update. We
deliberately do not restart the process from inside it — uvicorn + venv on
Windows make process-respawn fragile. Instead we tell the operator to restart
the launcher; the launcher already reinstalls deps from requirements.txt on
each run, so 'apply update + restart' is fully automatic.
"""

from __future__ import annotations

import asyncio
import fnmatch
import io
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

import httpx

from . import config as config_mod

ROOT = Path(__file__).resolve().parent.parent

log = logging.getLogger("dws.updater")

# Upstream repo for tarball-mode updates. Hard-coded by default because the
# tarball install has no `git remote` to read from; env vars let forks rebrand
# without code changes.
UPSTREAM_OWNER = os.environ.get("DWS_UPSTREAM_OWNER", "enfierno21")
UPSTREAM_REPO = os.environ.get("DWS_UPSTREAM_REPO", "DarkWebScanner")
DEFAULT_BRANCH = os.environ.get("DWS_UPSTREAM_BRANCH", "main")
USER_AGENT = "DarkWebScanner-Updater"

INSTALLED_SHA_FILE = ROOT / "data" / "installed_sha.txt"
BACKUP_DIR = ROOT / "data" / ".update_backup"

# Within these top-level directories, files present locally but missing
# upstream are removed during apply so upstream deletions propagate. Outside
# these dirs we overlay only — never remove — to keep operator-managed files
# (custom scripts, README edits, etc.) intact.
_PRUNABLE_DIRS = ("backend", "frontend", "tests")

# Paths the tarball-mode extractor must never touch — operator data, virtual
# envs, build caches. Matched as path-prefixes (forward slashes, relative to
# ROOT) and as basename glob patterns.
_PRESERVE_PREFIXES = (
    "data/", "data",
    ".venv/", "backend/.venv/",
    ".pytest_cache/",
    "__pycache__/", "backend/__pycache__/", "tests/__pycache__/",
    ".git/",
)
_PRESERVE_GLOBS = ("*.db", "*.db-wal", "*.db-shm", "*.pyc", "*.pyo", ".DS_Store")

# Cache for the upstream commit lookup. GitHub's anonymous REST limit is
# 60 req/hour/IP; the Config tab fires a status check on every navigation.
_LATEST_CACHE_TTL = 60.0
_latest_cache: dict = {"ts": 0.0, "branch": None, "value": None}

# Serialize concurrent apply attempts so a double-click can't half-apply.
_apply_lock = asyncio.Lock()


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


def _short_err(e: Exception) -> str:
    """Trim verbose exception strings (httpx in particular) for UI display."""
    cls = e.__class__.__name__
    msg = (str(e) or "").split("\n", 1)[0].strip()
    out = f"{cls}: {msg}" if msg else cls
    return out[:200]


def _get_github_token() -> str:
    """Read the GitHub PAT from config (decrypted). Empty if unset or DB
    unavailable. Lets the updater authenticate against private upstream repos."""
    try:
        return (config_mod.get_full().get("github_token") or "").strip()
    except Exception:
        return ""


def _auth_headers() -> dict:
    token = _get_github_token()
    return {"Authorization": f"Bearer {token}"} if token else {}


def _diagnose_http_error(e: Exception) -> str:
    """Append a setup hint when the upstream call hit a likely auth wall.
    Empty repo or wrong branch will also surface as 404, so we only suggest
    the token path when no token is currently configured."""
    text = str(e)
    if "404" in text and not _get_github_token():
        return " (private repo? configure a GitHub token in this card)"
    if "401" in text or "403" in text:
        return " (token rejected — check it has `repo` read scope)"
    return ""


# ── git mode ─────────────────────────────────────────────────────────────────

async def _git_status() -> dict:
    rc, branch, _ = await _git("rev-parse", "--abbrev-ref", "HEAD")
    if rc != 0 or not branch:
        return {"is_repo": True, "available": True, "mode": "git",
                "error": "could not determine current branch"}

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
        "available": True,
        "mode": "git",
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


async def _git_apply() -> dict:
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


# ── tarball mode ─────────────────────────────────────────────────────────────

def _read_installed_sha() -> str | None:
    try:
        text = INSTALLED_SHA_FILE.read_text().strip()
        return text or None
    except (FileNotFoundError, OSError):
        return None


def _write_installed_sha(sha: str) -> None:
    INSTALLED_SHA_FILE.parent.mkdir(parents=True, exist_ok=True)
    INSTALLED_SHA_FILE.write_text(sha + "\n")


async def _fetch_latest_commit(branch: str) -> dict:
    """Returns {'sha': full, 'short': 7-char, 'subject': first-line}."""
    url = f"https://api.github.com/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/commits/{branch}"
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        **_auth_headers(),
    }
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(url, headers=headers)
    r.raise_for_status()
    j = r.json()
    sha = j["sha"]
    msg = (j.get("commit") or {}).get("message", "") or ""
    return {"sha": sha, "short": sha[:7], "subject": msg.splitlines()[0] if msg else ""}


async def _fetch_latest_commit_cached(branch: str, *, force: bool) -> dict:
    now = time.monotonic()
    cached = _latest_cache
    if (not force and cached["value"] is not None
            and cached["branch"] == branch
            and now - cached["ts"] < _LATEST_CACHE_TTL):
        return cached["value"]
    value = await _fetch_latest_commit(branch)
    _latest_cache.update({"ts": now, "branch": branch, "value": value})
    return value


async def _download_tarball(sha: str) -> bytes:
    # The /tarball/ API endpoint accepts the same Bearer token as /commits and
    # works for both public and private repos, redirecting to the signed CDN
    # URL. codeload.github.com would require a separate auth path for private
    # repos — using the API endpoint avoids that branching.
    url = f"https://api.github.com/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/tarball/{sha}"
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        **_auth_headers(),
    }
    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        r = await client.get(url, headers=headers)
    r.raise_for_status()
    return r.content


def _is_preserved(rel_path: str) -> bool:
    """True if this relative path (forward slashes) must NOT be touched by the
    tarball overlay — operator data, venvs, caches."""
    norm = rel_path.replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    for prefix in _PRESERVE_PREFIXES:
        if norm == prefix.rstrip("/") or norm.startswith(prefix):
            return True
    name = norm.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, pat) for pat in _PRESERVE_GLOBS)


def _in_prunable_dir(rel_path: str) -> bool:
    return any(rel_path == d or rel_path.startswith(d + "/") for d in _PRUNABLE_DIRS)


def _walk_files(root: Path, *, only_prunable: bool) -> set[str]:
    """All non-preserved files under `root` as relative POSIX paths.
    If only_prunable, restrict to `_PRUNABLE_DIRS` subtrees."""
    out: set[str] = set()
    if only_prunable:
        roots = [root / d for d in _PRUNABLE_DIRS if (root / d).is_dir()]
    else:
        roots = [root]
    for base in roots:
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if _is_preserved(rel):
                continue
            out.add(rel)
    return out


def _extract_tarball_to_staging(data: bytes, dest: Path, expected_sha: str) -> Path:
    """Extract the tarball into `dest`. Validates that the top-level dir name
    contains the expected short SHA. Returns the path of the top-level dir."""
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    top_name: str | None = None
    short = expected_sha[:7] if expected_sha else ""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        members = tf.getmembers()
        if not members:
            raise RuntimeError("empty tarball")
        top_name = members[0].name.split("/", 1)[0]
        if short and short not in top_name:
            raise RuntimeError(
                f"tarball top dir {top_name!r} does not contain expected sha {short}"
            )
        for m in members:
            target = dest / m.name
            try:
                target_resolved = target.resolve()
                target_resolved.relative_to(dest_resolved)
            except (ValueError, OSError):
                continue  # path traversal guard
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif m.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(m)
                if src is None:
                    continue
                with open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
                try:
                    os.chmod(target, m.mode & 0o777)
                except OSError:
                    pass
    assert top_name is not None
    return dest / top_name


def _snapshot_paths(paths: set[str], src_root: Path, snapshot_dir: Path) -> None:
    """Copy `paths` from src_root to snapshot_dir, preserving structure."""
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    for rel in paths:
        src = src_root / rel
        if not src.is_file():
            continue
        dst = snapshot_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def _restore_snapshot(snapshot_dir: Path, dest_root: Path) -> int:
    """Restore every file from snapshot_dir back into dest_root. Best-effort:
    individual copy failures are logged and skipped. Returns count restored."""
    if not snapshot_dir.is_dir():
        return 0
    restored = 0
    for src in snapshot_dir.rglob("*"):
        if not src.is_file():
            continue
        rel = src.relative_to(snapshot_dir)
        dst = dest_root / rel
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            restored += 1
        except OSError as e:
            log.warning("restore: failed to write %s: %s", rel, e)
    return restored


def _apply_overlay_and_prune(
    extracted_root: Path,
    dest_root: Path,
    tarball_files: set[str],
    to_remove: set[str],
) -> tuple[int, int]:
    """Copy upstream files over the working tree, then prune removed ones.
    Returns (copied, removed). Raises on overlay copy failure so the caller
    can roll back; pruning failures are best-effort and logged."""
    copied = 0
    for rel in tarball_files:
        src = extracted_root / rel
        if not src.is_file():
            continue
        dst = dest_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied += 1

    removed = 0
    for rel in to_remove:
        target = dest_root / rel
        try:
            target.unlink()
            removed += 1
        except FileNotFoundError:
            pass
        except OSError as e:
            log.warning("prune: could not remove %s: %s", rel, e)
    return copied, removed


async def _tarball_status(*, force_refresh: bool) -> dict:
    branch = DEFAULT_BRANCH
    installed = _read_installed_sha()

    base = {
        "is_repo": False,
        "available": True,
        "mode": "tarball",
        "branch": branch,
        "head_sha": installed[:7] if installed else None,
        "head_full": installed,
        "head_subject": None,
        "ahead": 0,
        "dirty": False,
    }

    try:
        latest = await _fetch_latest_commit_cached(branch, force=force_refresh)
    except Exception as e:
        log.warning("updater: github api failed: %s", _short_err(e))
        return {**base, "upstream_sha": None, "behind": 0, "fetched": False,
                "fetch_error": _short_err(e) + _diagnose_http_error(e),
                "update_available": False}

    if installed is None:
        # First run after upgrading to the tarball-aware updater: we don't yet
        # know what's installed, so offer the apply to pin the SHA file.
        update_available = True
        head_subject: str | None = "(installed commit unknown — apply to pin)"
    else:
        update_available = installed != latest["sha"]
        head_subject = None

    return {
        **base,
        "head_subject": head_subject,
        "upstream_sha": latest["short"],
        "upstream_subject": latest["subject"],
        "behind": 1 if update_available else 0,
        "fetched": True,
        "fetch_error": None,
        "update_available": update_available,
    }


async def _tarball_apply() -> dict:
    if _apply_lock.locked():
        return {"ok": False, "error": "an update is already in progress"}
    async with _apply_lock:
        return await _tarball_apply_locked()


async def _tarball_apply_locked() -> dict:
    branch = DEFAULT_BRANCH
    installed = _read_installed_sha()
    before_short = installed[:7] if installed else "unknown"

    try:
        # Always force-refresh on apply: never act on stale comparison data.
        latest = await _fetch_latest_commit_cached(branch, force=True)
    except Exception as e:
        log.warning("updater: github api failed: %s", _short_err(e))
        return {"ok": False,
                "error": f"github api: {_short_err(e)}{_diagnose_http_error(e)}"}

    if installed and installed == latest["sha"]:
        return {"ok": False, "error": "already at latest commit"}

    log.info("updater: applying %s -> %s", before_short, latest["short"])

    try:
        data = await _download_tarball(latest["sha"])
    except Exception as e:
        log.warning("updater: download failed: %s", _short_err(e))
        return {"ok": False, "error": f"download failed: {_short_err(e)}"}

    def _do_apply() -> tuple[int, int]:
        with tempfile.TemporaryDirectory(prefix="dws-update-") as staging:
            extract_dir = Path(staging) / "extract"
            extracted_root = _extract_tarball_to_staging(data, extract_dir, latest["sha"])

            tarball_files = _walk_files(extracted_root, only_prunable=False)
            local_in_prunable = _walk_files(ROOT, only_prunable=True)
            tarball_in_prunable = {f for f in tarball_files if _in_prunable_dir(f)}
            to_remove = local_in_prunable - tarball_in_prunable

            # Snapshot every file we are about to touch so we can roll back.
            files_to_overwrite = {f for f in tarball_files if (ROOT / f).is_file()}
            to_snapshot = files_to_overwrite | to_remove

            shutil.rmtree(BACKUP_DIR, ignore_errors=True)
            _snapshot_paths(to_snapshot, ROOT, BACKUP_DIR)

            try:
                return _apply_overlay_and_prune(
                    extracted_root, ROOT, tarball_files, to_remove,
                )
            except Exception:
                restored = _restore_snapshot(BACKUP_DIR, ROOT)
                log.warning("updater: rolled back %d files after apply failure", restored)
                raise

    try:
        copied, removed = await asyncio.to_thread(_do_apply)
    except Exception as e:
        log.exception("updater: apply failed")
        return {"ok": False, "error": f"apply failed (rolled back): {_short_err(e)}"}

    _write_installed_sha(latest["sha"])
    log.info("updater: applied %s -> %s (%d files written, %d removed)",
             before_short, latest["short"], copied, removed)

    return {
        "ok": True,
        "before_sha": before_short,
        "after_sha": latest["short"],
        "summary": [f"{latest['short']} {latest['subject']}".rstrip()],
        "files_changed": copied,
        "files_removed": removed,
        "restart_needed": True,
    }


# ── public API ───────────────────────────────────────────────────────────────

async def status(*, force_refresh: bool = False) -> dict:
    if await asyncio.to_thread(_is_repo_sync):
        return await _git_status()
    return await _tarball_status(force_refresh=force_refresh)


async def apply_update() -> dict:
    if await asyncio.to_thread(_is_repo_sync):
        return await _git_apply()
    return await _tarball_apply()
