import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import quote

import httpx

from . import db, severity as sev_mod

log = logging.getLogger("dws.scanner")

HIBP_BASE = "https://haveibeenpwned.com/api/v3"


class HIBPError(Exception):
    pass


class HIBPAuthError(HIBPError):
    pass


class HIBPRateLimitError(HIBPError):
    def __init__(self, retry_after: float):
        super().__init__(f"rate limited; retry after {retry_after}s")
        self.retry_after = retry_after


class _RateLimiter:
    """Simple async limiter: enforce a minimum gap between calls based on RPM."""

    def __init__(self, rpm: int):
        self.min_gap = 60.0 / max(1, rpm)
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self.min_gap:
                await asyncio.sleep(self.min_gap - elapsed)
            self._last = time.monotonic()


class HIBPClient:
    def __init__(self, api_key: str, *, rpm: int = 10,
                 user_agent: str = "DarkWebScanner/1.0"):
        if not api_key:
            raise HIBPAuthError("HIBP API key is not configured")
        self.api_key = api_key
        self.rpm = rpm
        self.user_agent = user_agent
        self._limiter = _RateLimiter(rpm)
        self._client = httpx.AsyncClient(
            base_url=HIBP_BASE,
            headers={
                "hibp-api-key": api_key,
                "User-Agent": user_agent,
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(30.0),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HIBPClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def _get(self, path: str, params: Optional[dict] = None) -> Any:
        attempt = 0
        while True:
            attempt += 1
            await self._limiter.wait()
            try:
                resp = await self._client.get(path, params=params)
            except httpx.RequestError as e:
                if attempt >= 3:
                    raise HIBPError(f"network error: {e}") from e
                await asyncio.sleep(2 ** attempt)
                continue

            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                return None  # "no record" — HIBP convention
            if resp.status_code == 401:
                raise HIBPAuthError("invalid HIBP API key")
            if resp.status_code == 403:
                raise HIBPAuthError("forbidden — check API key / user-agent")
            if resp.status_code == 429:
                retry = float(resp.headers.get("retry-after", "6"))
                if attempt >= 4:
                    raise HIBPRateLimitError(retry)
                log.warning("HIBP 429; sleeping %.1fs", retry)
                await asyncio.sleep(retry + 0.25)
                continue
            if resp.status_code in (502, 503, 504):
                if attempt >= 4:
                    raise HIBPError(f"HIBP {resp.status_code} (retries exhausted)")
                await asyncio.sleep(2 ** attempt)
                continue
            raise HIBPError(f"HIBP HTTP {resp.status_code}: {resp.text[:200]}")

    async def breached_account(self, email: str) -> list[dict]:
        path = f"/breachedaccount/{quote(email, safe='')}"
        data = await self._get(path, params={"truncateResponse": "false"})
        return data or []

    async def paste_account(self, email: str) -> list[dict]:
        path = f"/pasteaccount/{quote(email, safe='')}"
        data = await self._get(path)
        return data or []


# ── scan orchestration ────────────────────────────────────────────────────────

ProgressCb = Callable[[dict], Awaitable[None]]


@dataclass
class ScanResult:
    run_id: int
    email_count: int
    new_breach_findings: list[dict] = field(default_factory=list)
    new_paste_findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def _emit(cb: Optional[ProgressCb], event: dict) -> None:
    if cb is None:
        return
    try:
        await cb(event)
    except Exception:
        log.exception("progress callback failed")


async def run_scan(
    *,
    cfg: dict,
    emails: list[str],
    persist: bool,
    progress: Optional[ProgressCb] = None,
) -> ScanResult:
    """
    Scan the given emails. If `persist` is True, results are stored to the DB
    (so subsequent scans can diff for "new" findings). Otherwise this is a
    one-shot read-only report.
    """
    if not emails:
        run_id = db.create_run(0, persist)
        db.finish_run(run_id, new_breaches=0, new_pastes=0, status="ok")
        return ScanResult(run_id=run_id, email_count=0)

    run_id = db.create_run(len(emails), persist)
    result = ScanResult(run_id=run_id, email_count=len(emails))

    try:
        client = HIBPClient(
            api_key=cfg["hibp_api_key"],
            rpm=int(cfg.get("hibp_rpm") or 10),
            user_agent=cfg.get("user_agent") or "DarkWebScanner/1.0",
        )
    except HIBPAuthError as e:
        db.finish_run(run_id, new_breaches=0, new_pastes=0, status="error", error=str(e))
        result.errors.append(str(e))
        await _emit(progress, {"type": "scan_finished", "run_id": run_id,
                               "status": "error", "error": str(e)})
        return result

    include_pastes = bool(cfg.get("include_pastes"))

    await _emit(progress, {
        "type": "scan_started", "run_id": run_id,
        "email_count": len(emails), "include_pastes": include_pastes, "persist": persist,
    })

    try:
        async with client:
            for idx, email in enumerate(emails, start=1):
                await _emit(progress, {
                    "type": "scan_progress", "run_id": run_id,
                    "email": email, "index": idx, "total": len(emails),
                })

                try:
                    breaches = await client.breached_account(email)
                except HIBPError as e:
                    msg = f"{email}: {e}"
                    log.warning(msg)
                    result.errors.append(msg)
                    await _emit(progress, {"type": "scan_error", "run_id": run_id,
                                           "email": email, "error": str(e)})
                    if isinstance(e, HIBPAuthError):
                        raise
                    continue

                known = db.email_breach_names(email) if persist else set()
                for b in breaches:
                    name = b.get("Name")
                    if not name:
                        continue
                    if persist:
                        db.upsert_breach(b)
                        is_new = db.link_email_breach(email, name)
                    else:
                        is_new = name not in known
                    if is_new:
                        finding = {
                            "email": email,
                            "breach_name": name,
                            "title": b.get("Title"),
                            "domain": b.get("Domain"),
                            "breach_date": b.get("BreachDate"),
                            "data_classes": b.get("DataClasses") or [],
                            "is_sensitive": bool(b.get("IsSensitive")),
                            "severity": sev_mod.compute(b),
                        }
                        result.new_breach_findings.append(finding)
                        await _emit(progress, {"type": "finding", "kind": "breach",
                                               "run_id": run_id, **finding})

                if include_pastes:
                    try:
                        pastes = await client.paste_account(email)
                    except HIBPError as e:
                        msg = f"{email} (pastes): {e}"
                        log.warning(msg)
                        result.errors.append(msg)
                        pastes = []

                    known_p = db.email_paste_ids(email) if persist else set()
                    for p in pastes:
                        pid = p.get("Id")
                        if not pid:
                            continue
                        if persist:
                            db.upsert_paste(p)
                            is_new = db.link_email_paste(email, pid)
                        else:
                            is_new = pid not in known_p
                        if is_new:
                            finding = {
                                "email": email,
                                "paste_id": pid,
                                "source": p.get("Source"),
                                "title": p.get("Title"),
                                "paste_date": p.get("Date"),
                                "email_count": p.get("EmailCount"),
                                "severity": sev_mod.compute_paste(p),
                            }
                            result.new_paste_findings.append(finding)
                            await _emit(progress, {"type": "finding", "kind": "paste",
                                                   "run_id": run_id, **finding})

        db.finish_run(
            run_id,
            new_breaches=len(result.new_breach_findings),
            new_pastes=len(result.new_paste_findings),
            status="ok" if not result.errors else "partial",
            error="; ".join(result.errors) if result.errors else None,
        )
        await _emit(progress, {
            "type": "scan_finished", "run_id": run_id,
            "status": "ok" if not result.errors else "partial",
            "new_breaches": len(result.new_breach_findings),
            "new_pastes": len(result.new_paste_findings),
            "errors": result.errors,
        })
    except HIBPAuthError as e:
        db.finish_run(run_id, new_breaches=len(result.new_breach_findings),
                      new_pastes=len(result.new_paste_findings),
                      status="error", error=str(e))
        result.errors.append(str(e))
        await _emit(progress, {"type": "scan_finished", "run_id": run_id,
                               "status": "error", "error": str(e)})
    except Exception as e:
        log.exception("scan failed")
        db.finish_run(run_id, new_breaches=len(result.new_breach_findings),
                      new_pastes=len(result.new_paste_findings),
                      status="error", error=str(e))
        result.errors.append(str(e))
        await _emit(progress, {"type": "scan_finished", "run_id": run_id,
                               "status": "error", "error": str(e)})

    return result
