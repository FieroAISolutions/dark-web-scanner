import pytest
from starlette.websockets import WebSocketDisconnect


@pytest.mark.parametrize("origin", [
    "https://foreign.invalid", "http://testserver:7071", "https://testserver",
    "null", "", "http://testserver@foreign.invalid", "http://testserver/path",
])
def test_http_and_websocket_reject_nonmatching_origins(client, origin):
    response = client.post("/api/auth/ws-ticket", headers={"Origin": origin})
    assert response.status_code == 403
    with pytest.raises(WebSocketDisconnect) as failure:
        with client.websocket_connect("/ws", headers={"Origin": origin}):
            pytest.fail("untrusted Origin was accepted")
    assert failure.value.code == 1008


@pytest.mark.parametrize("host", [
    "foreign.invalid", "testserver:bad", "testserver@foreign.invalid", "",
    "testserver/path", "testserver?query=1",
])
def test_http_and_websocket_reject_untrusted_hosts(client, host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 400
    with pytest.raises(WebSocketDisconnect) as failure:
        with client.websocket_connect("/ws", headers={"Host": host}):
            pytest.fail("untrusted Host was accepted")
    assert failure.value.code == 1008


@pytest.mark.parametrize("headers", [{}, {"Origin": "http://testserver"},
                                     {"Origin": "http://testserver:80"}])
def test_native_and_same_origin_clients_still_work(client, headers):
    response = client.post("/api/auth/ws-ticket", headers=headers)
    assert response.status_code == 200
    with client.websocket_connect("/ws", headers=headers) as ws:
        assert ws.receive_json()["type"] == "hello"


def test_rejected_origin_does_not_consume_websocket_ticket(client):
    ticket = client.post("/api/auth/ws-ticket").json()["ticket"]
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws?ticket={ticket}",
                                      headers={"Origin": "https://foreign.invalid"}):
            pytest.fail("foreign Origin accepted")
    client.cookies.clear()
    with client.websocket_connect(f"/ws?ticket={ticket}") as ws:
        assert ws.receive_json()["type"] == "hello"


def test_missing_origin_does_not_bypass_auth(anon_client):
    assert anon_client.post("/api/auth/ws-ticket").status_code == 401
    with pytest.raises(WebSocketDisconnect):
        with anon_client.websocket_connect("/ws"):
            pytest.fail("unauthenticated native client accepted")
