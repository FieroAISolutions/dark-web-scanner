import asyncio
import logging
import os
import re
import secrets as py_secrets
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import (Depends, FastAPI, HTTPException, Request, Response,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import (alerts, auth, config as config_mod, db, log_redact, reports,
               scanner, scheduler as sched_mod, updater)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log_redact.install()
log = logging.getLogger("dws.main")

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"

# Per-process build stamp; substituted into index.html so cached JS/CSS from
# previous server runs gets invalidated automatically on restart.
BUILD_STAMP = os.environ.get("DWS_BUILD_STAMP") or str(int(time.time()))

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

# Hosts that map to this loopback service. Anything else is rejected to defend
# against DNS-rebinding attacks pointing a foreign hostname at 127.0.0.1.
ALLOWED_HOST_NAMES = {"localhost", "127.0.0.1"}

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


# ── pubsub for websocket ──────────────────────────────────────────────────────

class Hub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def add(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.add(ws)

    async def remove(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, event: dict) -> None:
        async with self._lock:
            clients = list(self._clients)
        if not clients:
            return
        dead = []
        for ws in clients:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)


hub = Hub()


# ── one-shot WebSocket tickets ────────────────────────────────────────────────
#
# Browsers don't always attach cookies to the WebSocket upgrade request — some
# privacy-focused builds and many extensions strip them, even on same-origin.
# To keep WS auth deterministic, the SPA fetches a single-use ticket via an
# authenticated HTTP POST, then opens the WS with ?ticket=… . The cookie path
# still works when the browser cooperates.

_WS_TICKET_TTL = 60.0  # seconds
_ws_tickets: dict[str, float] = {}
_ws_tickets_lock = asyncio.Lock()


async def _issue_ws_ticket() -> str:
    ticket = py_secrets.token_urlsafe(32)
    async with _ws_tickets_lock:
        now = time.time()
        # Drop expired tickets opportunistically.
        for k in [k for k, exp in _ws_tickets.items() if exp <= now]:
            del _ws_tickets[k]
        _ws_tickets[ticket] = now + _WS_TICKET_TTL
    return ticket


async def _consume_ws_ticket(ticket: str) -> bool:
    if not ticket:
        return False
    async with _ws_tickets_lock:
        exp = _ws_tickets.pop(ticket, None)
    if exp is None:
        return False
    return exp > time.time()


# ── scan orchestration ───────────────────────────────────────────────────────

_scan_lock = asyncio.Lock()


async def _execute_scan(emails: list[str], persist: bool) -> dict:
    cfg = config_mod.get_full()
    if not cfg.get("hibp_api_key"):
        raise HTTPException(status_code=400, detail="HIBP API key not configured")
    if not emails:
        raise HTTPException(status_code=400, detail="No emails provided")
    if _scan_lock.locked():
        raise HTTPException(status_code=409, detail="A scan is already running")

    run_id_fut: asyncio.Future = asyncio.get_running_loop().create_future()

    async def progress(event: dict) -> None:
        if event.get("type") == "scan_started" and not run_id_fut.done():
            run_id_fut.set_result(event.get("run_id"))
        await hub.broadcast(event)

    async def runner() -> None:
        result = None
        try:
            async with _scan_lock:
                result = await scanner.run_scan(
                    cfg=cfg, emails=emails, persist=persist, progress=progress,
                )
                if persist and cfg.get("alert_on_new") and (
                    result.new_breach_findings or result.new_paste_findings
                ):
                    status_ = await alerts.alert_new_findings(
                        cfg, result.new_breach_findings, result.new_paste_findings
                    )
                    await hub.broadcast({
                        "type": "alert_sent", "run_id": result.run_id, "status": status_,
                    })
        finally:
            if not run_id_fut.done():
                run_id_fut.set_result(result.run_id if result else None)

    asyncio.create_task(runner())
    try:
        run_id = await asyncio.wait_for(run_id_fut, timeout=10.0)
    except asyncio.TimeoutError:
        run_id = None
    return {"run_id": run_id, "email_count": len(emails), "persist": persist}


async def _scheduled_run() -> None:
    cfg = config_mod.get_full()
    if not cfg.get("hibp_api_key"):
        log.warning("scheduled scan skipped: no API key")
        return
    emails = db.get_emails()
    if not emails:
        log.info("scheduled scan skipped: no monitored emails")
        return
    if _scan_lock.locked():
        log.info("scheduled scan skipped: another scan running")
        return

    async def progress(event: dict) -> None:
        await hub.broadcast(event)

    async with _scan_lock:
        result = await scanner.run_scan(
            cfg=cfg, emails=emails, persist=True, progress=progress,
        )
        if cfg.get("alert_on_new") and (
            result.new_breach_findings or result.new_paste_findings
        ):
            status_ = await alerts.alert_new_findings(
                cfg, result.new_breach_findings, result.new_paste_findings
            )
            await hub.broadcast({
                "type": "alert_sent", "run_id": result.run_id, "status": status_,
            })


scheduler = sched_mod.ScanScheduler(_scheduled_run)


# ── lifespan ──────────────────────────────────────────────────────────────────

def _print_setup_banner(token: str, port: int) -> None:
    bar = "─" * 70
    msg = (
        f"\n{bar}\n"
        f"  DarkWebScanner — first-run admin token created.\n\n"
        f"  Open this URL once to authenticate (token will be set as a cookie):\n"
        f"    http://localhost:{port}/?token={token}\n\n"
        f"  Token also saved to: {auth.TOKEN_FILE}\n"
        f"  KEEP THIS FILE SAFE. Anyone with it can read your scanner data.\n"
        f"{bar}\n"
    )
    print(msg, flush=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    config_mod.migrate_legacy_secrets()
    new_token = auth.ensure_initial_token()
    if new_token:
        port = getattr(app.state, "port", None) or int(os.environ.get("DWS_PORT", "7070"))
        _print_setup_banner(new_token, port)

    cfg = config_mod.get_full()
    scheduler.start()
    scheduler.apply(enabled=bool(cfg["enabled"]), interval_hours=cfg["interval_hours"])
    log.info("DarkWebScanner ready")
    try:
        yield
    finally:
        scheduler.shutdown()


app = FastAPI(title="DarkWebScanner", lifespan=lifespan)


# ── middlewares ───────────────────────────────────────────────────────────────

@app.middleware("http")
async def host_and_csrf_guard(request: Request, call_next):
    """
    Rejects non-loopback Host headers (DNS rebinding defence) and validates the
    Origin header on state-changing requests (CSRF defence). Static and
    websocket endpoints follow the same rules.
    """
    host_header = (request.headers.get("host") or "").split(":")[0].lower()
    if host_header and host_header not in ALLOWED_HOST_NAMES:
        return Response(status_code=400, content="invalid Host header")

    if request.method not in SAFE_METHODS:
        origin = request.headers.get("origin")
        if origin:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(origin)
                if parsed.hostname not in ALLOWED_HOST_NAMES:
                    return Response(status_code=403, content="invalid Origin")
            except Exception:
                return Response(status_code=403, content="invalid Origin")
        # If no Origin header at all, the caller is non-browser — that's fine,
        # they'll still need a valid auth token to do anything.

    response = await call_next(request)
    return response


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


# ── models ────────────────────────────────────────────────────────────────────

class EmailListReq(BaseModel):
    emails: list[str] = Field(default_factory=list)
    group_id: Optional[int] = None


class ScanReq(BaseModel):
    emails: Optional[list[str]] = None
    persist: bool = True
    group_id: Optional[int] = None  # if set, scan only this group's emails


class GroupCreateReq(BaseModel):
    name: str
    description: str = ""


class GroupUpdateReq(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class EmailGroupReq(BaseModel):
    group_id: Optional[int] = None  # null moves to "ungrouped"


class LoginReq(BaseModel):
    token: str  # accepts either the recovery token or the configured password


class SetPasswordReq(BaseModel):
    password: Optional[str] = None  # new password (required for set-password)
    current: Optional[str] = None   # required when changing or clearing an existing password


# ── routes: index + static ────────────────────────────────────────────────────

_index_template: Optional[str] = None


def _render_index() -> str:
    """Read index.html and substitute the build stamp (read once, cached)."""
    global _index_template
    if _index_template is None:
        _index_template = (FRONTEND / "index.html").read_text(encoding="utf-8")
    return _index_template.replace("__BUILD__", BUILD_STAMP)


@app.get("/")
async def index(request: Request):
    """
    Serves the SPA. If a `?token=` query param is supplied and matches the
    recovery token, sets the auth cookie and redirects to a clean URL so the
    token doesn't sit in browser history. (Passwords are only accepted via
    POST /api/auth/login.)
    """
    qs_token = request.query_params.get("token")
    if qs_token and auth.verify_token(qs_token):
        resp = RedirectResponse(url="/", status_code=303)
        resp.set_cookie(value=qs_token, **auth.cookie_kwargs())
        return resp
    return Response(
        content=_render_index(),
        media_type="text/html; charset=utf-8",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


class _NoCacheStaticFiles(StaticFiles):
    """StaticFiles that forces revalidation, so updated JS/CSS land immediately
    after a server restart instead of being served from browser disk cache."""

    async def get_response(self, path: str, scope):
        resp = await super().get_response(path, scope)
        resp.headers["Cache-Control"] = "no-cache, must-revalidate"
        return resp


app.mount("/static", _NoCacheStaticFiles(directory=FRONTEND / "static"), name="static")


# ── routes: auth ──────────────────────────────────────────────────────────────

@app.get("/api/auth/status")
async def auth_status(request: Request):
    return {
        "authenticated": auth.verify_token(auth.extract_token(request)),
        "password_set": auth.has_password(),
    }


@app.post("/api/auth/login")
async def auth_login(payload: LoginReq, response: Response):
    """
    Accept either the recovery token or the configured password. On success,
    the cookie is set to the recovery token in either case so subsequent
    per-request checks remain a single SHA-256 compare (no bcrypt per request).
    """
    cred = (payload.token or "").strip()
    has_pw = auth.has_password()
    log.info("login attempt: cred_len=%d password_set=%s", len(cred), has_pw)
    if not cred:
        raise HTTPException(status_code=401, detail="missing credential")

    if auth.verify_token(cred):
        log.info("login success via recovery token")
        response.set_cookie(value=cred, **auth.cookie_kwargs())
        return {"ok": True, "method": "token", "password_set": has_pw}

    # Password verification calls bcrypt — run off the event loop so we don't
    # stall other concurrent requests (WebSocket pings, dashboard fetches).
    if await asyncio.to_thread(auth.verify_password, cred):
        recovery = auth.read_recovery_token()
        if not recovery:
            log.warning("password login succeeded but recovery token is missing on disk; "
                        "regenerating so the cookie can be set")
            recovery = auth.regenerate_token()
        log.info("login success via password")
        response.set_cookie(value=recovery, **auth.cookie_kwargs())
        return {"ok": True, "method": "password", "password_set": True}

    log.info("login failed: neither token nor password matched (password_set=%s)", has_pw)
    raise HTTPException(status_code=401, detail="invalid credential")


@app.post("/api/auth/logout")
async def auth_logout(response: Response):
    response.delete_cookie(key=auth.TOKEN_COOKIE, path="/")
    return {"ok": True}


@app.post("/api/auth/regenerate", dependencies=[Depends(auth.require_auth)])
async def auth_regenerate(response: Response):
    new_token = auth.regenerate_token()
    response.set_cookie(value=new_token, **auth.cookie_kwargs())
    return {"ok": True, "token": new_token, "saved_to": str(auth.TOKEN_FILE)}


@app.post("/api/auth/ws-ticket", dependencies=[Depends(auth.require_auth)])
async def auth_ws_ticket():
    """Issue a single-use, 60-second ticket the SPA can pass via ?ticket= when
    opening a WebSocket — bypasses browser quirks around cookies on WS upgrade."""
    return {"ticket": await _issue_ws_ticket(), "ttl_seconds": int(_WS_TICKET_TTL)}


@app.post("/api/auth/set-password", dependencies=[Depends(auth.require_auth)])
async def auth_set_password(payload: SetPasswordReq):
    log.info("set-password: request received")
    if not payload.password:
        raise HTTPException(status_code=400, detail="password is required")
    # If a password already exists, the caller must prove they know it.
    if auth.has_password():
        if not payload.current:
            raise HTTPException(status_code=403, detail="current password required")
        if not await asyncio.to_thread(auth.verify_password, payload.current):
            raise HTTPException(status_code=403, detail="current password required")
    try:
        await asyncio.to_thread(auth.set_password, payload.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log.info("set-password: success")
    return {"ok": True, "password_set": True}


@app.post("/api/auth/clear-password", dependencies=[Depends(auth.require_auth)])
async def auth_clear_password(payload: SetPasswordReq):
    if auth.has_password():
        if not payload.current:
            raise HTTPException(status_code=403, detail="current password required")
        if not await asyncio.to_thread(auth.verify_password, payload.current):
            raise HTTPException(status_code=403, detail="current password required")
    auth.clear_password()
    return {"ok": True, "password_set": False}


# ── routes: protected API ─────────────────────────────────────────────────────

protected = [Depends(auth.require_auth)]


@app.get("/api/health", dependencies=protected)
async def health():
    return {"ok": True}


def _normalize_emails(items: list[str]) -> tuple[list[str], list[str]]:
    valid, invalid = [], []
    seen = set()
    for raw in items or []:
        e = (raw or "").strip().lower()
        if not e:
            continue
        if not EMAIL_RE.match(e):
            invalid.append(raw)
            continue
        if e in seen:
            continue
        seen.add(e)
        valid.append(e)
    return valid, invalid


@app.get("/api/emails", dependencies=protected)
async def api_list_emails(group_id: Optional[int] = None):
    return {"emails": db.list_emails(group_id=group_id)}


@app.post("/api/emails", dependencies=protected)
async def api_add_emails(req: EmailListReq):
    valid, invalid = _normalize_emails(req.emails)
    if not valid:
        raise HTTPException(status_code=400,
                            detail=f"No valid emails. Invalid: {invalid}")
    if req.group_id is not None and db.get_group(req.group_id) is None:
        raise HTTPException(status_code=400, detail="unknown group_id")
    added, skipped = db.add_emails(valid, group_id=req.group_id)
    return {"added": added, "skipped": skipped, "invalid": invalid}


@app.delete("/api/emails/{email}", dependencies=protected)
async def api_remove_email(email: str):
    e = email.strip().lower()
    ok = db.remove_email(e)
    if not ok:
        raise HTTPException(status_code=404, detail="not monitored")
    return {"removed": e}


@app.patch("/api/emails/{email}/group", dependencies=protected)
async def api_set_email_group(email: str, req: EmailGroupReq):
    e = email.strip().lower()
    if req.group_id is not None and db.get_group(req.group_id) is None:
        raise HTTPException(status_code=400, detail="unknown group_id")
    ok = db.set_email_group(e, req.group_id)
    if not ok:
        raise HTTPException(status_code=404, detail="not monitored")
    return {"ok": True, "email": e, "group_id": req.group_id}


@app.get("/api/dashboard", dependencies=protected)
async def api_dashboard(group_id: Optional[int] = None):
    stats = db.dashboard_stats(group_id=group_id)
    stats["next_run_at"] = scheduler.next_run_time()
    stats["scan_in_progress"] = _scan_lock.locked()
    stats["recent_findings"] = db.list_findings(limit=10, group_id=group_id)
    stats["recent_runs"] = db.recent_runs(limit=5)
    stats["severity_counts"] = db.severity_counts(group_id=group_id)
    stats["group_id"] = group_id
    return stats


@app.get("/api/findings", dependencies=protected)
async def api_findings(limit: int = 200, group_id: Optional[int] = None):
    return {"findings": db.list_findings(
        limit=min(max(limit, 1), 1000), group_id=group_id)}


@app.get("/api/pastes", dependencies=protected)
async def api_pastes(limit: int = 200, group_id: Optional[int] = None):
    return {"pastes": db.list_pastes(
        limit=min(max(limit, 1), 1000), group_id=group_id)}


# ── routes: groups ────────────────────────────────────────────────────────────


@app.get("/api/groups", dependencies=protected)
async def api_list_groups():
    return {"groups": db.list_groups()}


@app.post("/api/groups", dependencies=protected)
async def api_create_group(req: GroupCreateReq):
    name = (req.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    if len(name) > 80:
        raise HTTPException(status_code=400, detail="name too long (max 80)")
    if db.get_group_by_name(name):
        raise HTTPException(status_code=409, detail="a group with that name already exists")
    gid = db.create_group(name=name, description=(req.description or "").strip())
    return {"id": gid, "name": name}


@app.patch("/api/groups/{group_id}", dependencies=protected)
async def api_update_group(group_id: int, req: GroupUpdateReq):
    existing = db.get_group(group_id)
    if not existing:
        raise HTTPException(status_code=404, detail="group not found")
    name = req.name.strip() if req.name is not None else None
    if name is not None:
        if not name:
            raise HTTPException(status_code=400, detail="name cannot be empty")
        if len(name) > 80:
            raise HTTPException(status_code=400, detail="name too long (max 80)")
        existing_other = db.get_group_by_name(name)
        if existing_other and existing_other["id"] != group_id:
            raise HTTPException(status_code=409, detail="another group already has that name")
    description = req.description.strip() if req.description is not None else None
    db.update_group(group_id, name=name, description=description)
    return db.get_group(group_id)


@app.delete("/api/groups/{group_id}", dependencies=protected)
async def api_delete_group(group_id: int):
    ok, err = db.delete_group(group_id)
    if not ok:
        raise HTTPException(status_code=400, detail=err)
    return {"ok": True}


@app.get("/api/scan/runs", dependencies=protected)
async def api_runs(limit: int = 20):
    return {"runs": db.recent_runs(limit=min(max(limit, 1), 100))}


@app.get("/api/scan/runs/{run_id}", dependencies=protected)
async def api_run(run_id: int):
    row = db.get_run(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    return row


@app.post("/api/scan", dependencies=protected)
async def api_scan(req: ScanReq):
    if req.emails is not None:
        valid, invalid = _normalize_emails(req.emails)
        if not valid:
            raise HTTPException(status_code=400,
                                detail=f"No valid emails. Invalid: {invalid}")
        emails = valid
    else:
        if req.group_id is not None and db.get_group(req.group_id) is None:
            raise HTTPException(status_code=400, detail="unknown group_id")
        emails = db.get_emails(group_id=req.group_id)
        if not emails:
            scope = f" in group {req.group_id}" if req.group_id is not None else ""
            raise HTTPException(status_code=400, detail=f"No monitored emails{scope}")
    return await _execute_scan(emails, persist=bool(req.persist))


@app.get("/api/config", dependencies=protected)
async def api_get_config():
    return config_mod.get_public()


@app.post("/api/config", dependencies=protected)
async def api_update_config(payload: dict):
    new_pub = config_mod.update(payload)
    cfg_full = config_mod.get_full()
    scheduler.apply(
        enabled=bool(cfg_full["enabled"]),
        interval_hours=int(cfg_full["interval_hours"]),
    )
    new_pub["next_run_at"] = scheduler.next_run_time()
    return new_pub


@app.post("/api/config/test-email", dependencies=protected)
async def api_test_email():
    cfg = config_mod.get_full()
    try:
        await alerts.send_email(
            cfg,
            subject="DarkWebScanner test email",
            text="This is a test email from DarkWebScanner. If you got it, SMTP works.",
            html="<p>This is a test email from <b>DarkWebScanner</b>. "
                 "If you got it, SMTP works.</p>",
        )
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── routes: reports ───────────────────────────────────────────────────────────


@app.get("/api/report", dependencies=protected)
async def api_report(group_id: Optional[int] = None, since: Optional[str] = None,
                     days: Optional[int] = None):
    """Render an HTML report scoped to a group + date range. Falls back to
    `days=N` (defaults to 30) when no since-date is given."""
    if group_id is not None and db.get_group(group_id) is None:
        raise HTTPException(status_code=400, detail="unknown group_id")
    try:
        since_norm = reports.parse_since(since) if since else reports.default_since(days or 30)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    data = reports.gather_report_data(group_id=group_id, since=since_norm)
    body = reports.render(data)
    return Response(
        content=body,
        media_type="text/html; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


# ── routes: updater ───────────────────────────────────────────────────────────


@app.get("/api/update/status", dependencies=protected)
async def api_update_status():
    return await updater.status()


@app.post("/api/update/apply", dependencies=protected)
async def api_update_apply():
    return await updater.apply_update()


@app.post("/api/config/test-webhook", dependencies=protected)
async def api_test_webhook():
    cfg = config_mod.get_full()
    try:
        await alerts.send_webhook(
            cfg,
            subject="DarkWebScanner test webhook",
            text="If you see this, the webhook is wired up correctly.",
            fields=[{"name": "Status", "value": "OK"}],
        )
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── websocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    # Auth precedence:
    #   1. ?ticket=… one-shot ticket (preferred — survives browser quirks
    #      where cookies aren't attached to WS upgrade requests).
    #   2. dws_token cookie.
    #   3. ?token=… recovery token (manual / debugging).
    cookie_token = ws.cookies.get(auth.TOKEN_COOKIE) or ""
    qs_ticket = ws.query_params.get("ticket") or ""
    qs_token = ws.query_params.get("token") or ""

    authed = False
    if qs_ticket and await _consume_ws_ticket(qs_ticket):
        authed = True
    elif cookie_token and auth.verify_token(cookie_token):
        authed = True
    elif qs_token and auth.verify_token(qs_token):
        authed = True

    if not authed:
        log.info("ws: rejected (no valid ticket/cookie/token)")
        await ws.close(code=1008)
        return

    await ws.accept()
    await hub.add(ws)
    try:
        await ws.send_json({"type": "hello", "ok": True})
        while True:
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                try:
                    await ws.send_json({"type": "ping"})
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        await hub.remove(ws)


# ── entrypoint ────────────────────────────────────────────────────────────────

def main():
    port = 7070
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    os.environ["DWS_PORT"] = str(port)
    app.state.port = port
    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=port,
        log_level="info",
        reload=False,
    )


if __name__ == "__main__":
    main()
