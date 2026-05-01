import asyncio
import logging
import os
import re
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import (Depends, FastAPI, HTTPException, Request, Response,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import (alerts, auth, config as config_mod, db, log_redact,
               scanner, scheduler as sched_mod)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log_redact.install()
log = logging.getLogger("dws.main")

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"

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


class ScanReq(BaseModel):
    emails: Optional[list[str]] = None
    persist: bool = True


class LoginReq(BaseModel):
    token: str


# ── routes: index + static ────────────────────────────────────────────────────

@app.get("/")
async def index(request: Request):
    """
    Serves the SPA. If a `?token=` query param is supplied and valid, sets the
    auth cookie and redirects to a clean URL so the token doesn't sit in
    browser history.
    """
    qs_token = request.query_params.get("token")
    if qs_token and auth.verify(qs_token):
        resp = RedirectResponse(url="/", status_code=303)
        resp.set_cookie(value=qs_token, **auth.cookie_kwargs())
        return resp
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND / "static"), name="static")


# ── routes: auth ──────────────────────────────────────────────────────────────

@app.get("/api/auth/status")
async def auth_status(request: Request):
    return {"authenticated": auth.verify(auth.extract_token(request))}


@app.post("/api/auth/login")
async def auth_login(payload: LoginReq, response: Response):
    if not auth.verify(payload.token or ""):
        raise HTTPException(status_code=401, detail="invalid token")
    response.set_cookie(value=payload.token, **auth.cookie_kwargs())
    return {"ok": True}


@app.post("/api/auth/logout")
async def auth_logout(response: Response):
    response.delete_cookie(key=auth.TOKEN_COOKIE, path="/")
    return {"ok": True}


@app.post("/api/auth/regenerate", dependencies=[Depends(auth.require_auth)])
async def auth_regenerate(response: Response):
    new_token = auth.regenerate_token()
    response.set_cookie(value=new_token, **auth.cookie_kwargs())
    return {"ok": True, "token": new_token, "saved_to": str(auth.TOKEN_FILE)}


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
async def api_list_emails():
    return {"emails": db.list_emails()}


@app.post("/api/emails", dependencies=protected)
async def api_add_emails(req: EmailListReq):
    valid, invalid = _normalize_emails(req.emails)
    if not valid:
        raise HTTPException(status_code=400,
                            detail=f"No valid emails. Invalid: {invalid}")
    added, skipped = db.add_emails(valid)
    return {"added": added, "skipped": skipped, "invalid": invalid}


@app.delete("/api/emails/{email}", dependencies=protected)
async def api_remove_email(email: str):
    e = email.strip().lower()
    ok = db.remove_email(e)
    if not ok:
        raise HTTPException(status_code=404, detail="not monitored")
    return {"removed": e}


@app.get("/api/dashboard", dependencies=protected)
async def api_dashboard():
    stats = db.dashboard_stats()
    stats["next_run_at"] = scheduler.next_run_time()
    stats["scan_in_progress"] = _scan_lock.locked()
    stats["recent_findings"] = db.list_findings(limit=10)
    stats["recent_runs"] = db.recent_runs(limit=5)
    stats["severity_counts"] = db.severity_counts()
    return stats


@app.get("/api/findings", dependencies=protected)
async def api_findings(limit: int = 200):
    return {"findings": db.list_findings(limit=min(max(limit, 1), 1000))}


@app.get("/api/pastes", dependencies=protected)
async def api_pastes(limit: int = 200):
    return {"pastes": db.list_pastes(limit=min(max(limit, 1), 1000))}


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
        emails = db.get_emails()
        if not emails:
            raise HTTPException(status_code=400, detail="No monitored emails")
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
    # Authenticate the WS connection from the cookie or query param BEFORE accepting.
    token = (ws.cookies.get(auth.TOKEN_COOKIE)
             or ws.query_params.get("token")
             or "")
    if not auth.verify(token):
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
