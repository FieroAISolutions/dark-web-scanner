import pytest
from fastapi.testclient import TestClient


def test_ws_ticket_endpoint_requires_auth(anon_client):
    r = anon_client.post("/api/auth/ws-ticket")
    assert r.status_code == 401


def test_ws_ticket_endpoint_returns_ticket(client):
    r = client.post("/api/auth/ws-ticket")
    assert r.status_code == 200
    body = r.json()
    assert "ticket" in body
    assert isinstance(body["ticket"], str)
    assert len(body["ticket"]) > 20
    assert body["ttl_seconds"] > 0


def test_ws_connects_with_ticket_no_cookie(client, monkeypatch):
    """A fresh client (no auth cookie) can still open the WS using a ticket."""
    r = client.post("/api/auth/ws-ticket")
    ticket = r.json()["ticket"]

    from backend import main as main_mod
    fresh = TestClient(main_mod.app)  # no cookies set
    with fresh.websocket_connect(f"/ws?ticket={ticket}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "hello"


def test_ws_ticket_is_single_use(client):
    from backend import main as main_mod

    r = client.post("/api/auth/ws-ticket")
    ticket = r.json()["ticket"]

    fresh = TestClient(main_mod.app)
    with fresh.websocket_connect(f"/ws?ticket={ticket}") as ws:
        ws.receive_json()  # consume hello

    # Reuse should fail
    with pytest.raises(Exception):
        with fresh.websocket_connect(f"/ws?ticket={ticket}"):
            pass


def test_ws_ticket_invalid_value_rejected(anon_client):
    try:
        with anon_client.websocket_connect("/ws?ticket=not-a-real-ticket"):
            assert False, "expected rejection"
    except Exception:
        pass


def test_ws_cookie_path_still_works(client):
    """The original cookie-based auth still works when the browser cooperates."""
    with client.websocket_connect("/ws") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "hello"


def test_ws_ticket_expiry(client, monkeypatch):
    from backend import main as main_mod

    # Shrink TTL to effectively zero so issued tickets are already stale
    monkeypatch.setattr(main_mod, "_WS_TICKET_TTL", 0.0)
    r = client.post("/api/auth/ws-ticket")
    ticket = r.json()["ticket"]

    fresh = TestClient(main_mod.app)
    with pytest.raises(Exception):
        with fresh.websocket_connect(f"/ws?ticket={ticket}"):
            pass
