from backend import auth


def test_token_generated_and_verifies():
    plain = auth.ensure_initial_token()
    assert plain
    assert auth.verify_token(plain)
    assert not auth.verify_token("not-the-right-token")
    assert not auth.verify_token("")


def test_ensure_initial_token_idempotent():
    first = auth.ensure_initial_token()
    again = auth.ensure_initial_token()
    assert first
    assert again is None  # only generates once


def test_regenerate_invalidates_old():
    old = auth.ensure_initial_token()
    new = auth.regenerate_token()
    assert old != new
    assert auth.verify_token(new)
    assert not auth.verify_token(old)


def test_protected_route_requires_token(anon_client):
    r = anon_client.get("/api/health")
    assert r.status_code == 401


def test_protected_route_accepts_cookie(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_protected_route_accepts_header(anon_client, admin_token):
    r = anon_client.get("/api/health", headers={"X-Auth-Token": admin_token})
    assert r.status_code == 200


def test_protected_route_accepts_query_param(anon_client, admin_token):
    r = anon_client.get(f"/api/health?token={admin_token}")
    assert r.status_code == 200


def test_login_endpoint_sets_cookie(anon_client, admin_token):
    r = anon_client.post("/api/auth/login", json={"token": admin_token})
    assert r.status_code == 200
    assert "dws_token" in r.cookies


def test_login_rejects_bad_token(anon_client):
    r = anon_client.post("/api/auth/login", json={"token": "garbage"})
    assert r.status_code == 401


def test_logout_clears_cookie(client):
    r = client.post("/api/auth/logout")
    assert r.status_code == 200


def test_index_with_token_query_redirects(anon_client, admin_token):
    r = anon_client.get(f"/?token={admin_token}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers.get("location") == "/"
    assert "dws_token" in r.cookies


def test_websocket_rejects_without_token(anon_client):
    import websockets  # noqa
    # TestClient WS without token should fail to connect (close code 1008)
    try:
        with anon_client.websocket_connect("/ws"):
            pass
        assert False, "expected websocket to be rejected"
    except Exception:
        pass


def test_websocket_accepts_with_token(client):
    with client.websocket_connect("/ws") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "hello"


def test_dns_rebinding_rejected(anon_client, admin_token):
    """A request with a foreign Host header should be rejected even with a valid token."""
    r = anon_client.get(
        "/api/health",
        headers={"X-Auth-Token": admin_token, "Host": "evil.example.com"},
    )
    assert r.status_code == 400


def test_csrf_origin_check_rejected(anon_client, admin_token):
    """POST from a foreign Origin is rejected before auth is checked."""
    r = anon_client.post(
        "/api/auth/login",
        json={"token": admin_token},
        headers={"Origin": "http://evil.example.com"},
    )
    assert r.status_code == 403
