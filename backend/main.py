import asyncio
import json
import logging
import re
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import alerts, config as config_mod, db, scanner, scheduler as sched_mod

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("dws.main")

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


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
                    status = await alerts.alert_new_findings(
                        cfg, result.new_breach_findings, result.new_paste_findings
                    )
                    await hub.broadcast({
                        "type": "alert_sent", "run_id": result.run_id, "status": status,
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
    """Called by APScheduler — scans all monitored emails."""
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
            status = await alerts.alert_new_findings(
                cfg, result.new_breach_findings, result.new_paste_findings
            )
            await hub.broadcast({
                "type": "alert_sent", "run_id": result.run_id, "status": status,
            })


scheduler = sched_mod.ScanScheduler(_scheduled_run)


# ── lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    cfg = config_mod.get_full()
    scheduler.start()
    scheduler.apply(enabled=bool(cfg["enabled"]), interval_hours=cfg["interval_hours"])
    log.info("DarkWebScanner ready")
    try:
        yield
    finally:
        scheduler.shutdown()


app = FastAPI(title="DarkWebScanner", lifespan=lifespan)


# ── models ────────────────────────────────────────────────────────────────────

class EmailListReq(BaseModel):
    emails: list[str] = Field(default_factory=list)


class ScanReq(BaseModel):
    emails: Optional[list[str]] = None
    persist: bool = True


# ── routes: static + index ────────────────────────────────────────────────────

@app.get("/")
async def index():
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND / "static"), name="static")


@app.get("/api/health")
async def health():
    return {"ok": True}


# ── routes: emails ────────────────────────────────────────────────────────────

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


@app.get("/api/emails")
async def api_list_emails():
    return {"emails": db.list_emails()}


@app.post("/api/emails")
async def api_add_emails(req: EmailListReq):
    valid, invalid = _normalize_emails(req.emails)
    if not valid:
        raise HTTPException(status_code=400,
                            detail=f"No valid emails. Invalid: {invalid}")
    added, skipped = db.add_emails(valid)
    return {"added": added, "skipped": skipped, "invalid": invalid}


@app.delete("/api/emails/{email}")
async def api_remove_email(email: str):
    e = email.strip().lower()
    ok = db.remove_email(e)
    if not ok:
        raise HTTPException(status_code=404, detail="not monitored")
    return {"removed": e}


# ── routes: dashboard / findings ──────────────────────────────────────────────

@app.get("/api/dashboard")
async def api_dashboard():
    stats = db.dashboard_stats()
    stats["next_run_at"] = scheduler.next_run_time()
    stats["scan_in_progress"] = _scan_lock.locked()
    stats["recent_findings"] = db.list_findings(limit=10)
    stats["recent_runs"] = db.recent_runs(limit=5)
    stats["severity_counts"] = db.severity_counts()
    return stats


@app.get("/api/findings")
async def api_findings(limit: int = 200):
    return {"findings": db.list_findings(limit=min(max(limit, 1), 1000))}


@app.get("/api/pastes")
async def api_pastes(limit: int = 200):
    return {"pastes": db.list_pastes(limit=min(max(limit, 1), 1000))}


@app.get("/api/scan/runs")
async def api_runs(limit: int = 20):
    return {"runs": db.recent_runs(limit=min(max(limit, 1), 100))}


@app.get("/api/scan/runs/{run_id}")
async def api_run(run_id: int):
    row = db.get_run(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    return row


# ── routes: scan ──────────────────────────────────────────────────────────────

@app.post("/api/scan")
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


# ── routes: config ────────────────────────────────────────────────────────────

@app.get("/api/config")
async def api_get_config():
    return config_mod.get_public()


@app.post("/api/config")
async def api_update_config(payload: dict):
    new_pub = config_mod.update(payload)
    cfg_full = config_mod.get_full()
    scheduler.apply(
        enabled=bool(cfg_full["enabled"]),
        interval_hours=int(cfg_full["interval_hours"]),
    )
    new_pub["next_run_at"] = scheduler.next_run_time()
    return new_pub


@app.post("/api/config/test-email")
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


@app.post("/api/config/test-webhook")
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
    await ws.accept()
    await hub.add(ws)
    try:
        await ws.send_json({"type": "hello", "ok": True})
        while True:
            # We don't expect client messages; just wait. Any message keeps it alive.
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
    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=port,
        log_level="info",
        reload=False,
    )


if __name__ == "__main__":
    main()
