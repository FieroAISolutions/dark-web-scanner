import pytest
from starlette.websockets import WebSocketDisconnect

from backend import auth, db, log_redact, reports, scanner, updater


def test_session_login_logout_and_rotation(anon_client, admin_token):
    response = anon_client.post('/api/auth/login', json={'token': admin_token})
    assert response.status_code == 200
    assert not response.cookies
    session = response.json()['session']
    assert session != admin_token
    anon_client.headers['X-Session-Token'] = session
    assert anon_client.get('/api/health').status_code == 200
    anon_client.post('/api/auth/logout')
    assert anon_client.get('/api/health').status_code == 401
    assert not auth.verify_session(admin_token)
    session = auth.issue_session()
    auth.regenerate_token()
    assert not auth.verify_session(session)


def test_cookie_and_url_credentials_are_rejected(anon_client, admin_token):
    anon_client.cookies.set('dws_token', admin_token)
    assert anon_client.get('/api/health').status_code == 401
    assert anon_client.get('/api/health', params={'token': admin_token}).status_code == 401
    with pytest.raises(WebSocketDisconnect):
        with anon_client.websocket_connect('/ws?token=' + admin_token):
            pytest.fail('recovery credential accepted from cookie or URL')


def test_login_throttles_before_verification(anon_client, monkeypatch):
    calls = []
    monkeypatch.setattr(auth, 'verify_credential', lambda value: calls.append(value) or False)
    for _ in range(10):
        assert anon_client.post('/api/auth/login', json={'token': 'bad'}).status_code == 401
    response = anon_client.post('/api/auth/login', json={'token': 'bad'})
    assert response.status_code == 429
    assert response.headers['Retry-After'] == '60'
    assert len(calls) == 10


def test_login_rejects_oversized_and_chunked_body(anon_client, monkeypatch):
    monkeypatch.setattr(auth, 'verify_credential', lambda value: pytest.fail('verified oversized credential'))
    assert anon_client.post('/api/auth/login', json={'token': 'x' * 513}).status_code == 422
    assert anon_client.post('/api/auth/login', json={'token': 'x' * 5000}).status_code == 413
    chunks = iter([b'{"token":"', b'x' * 5000, b'"}'])
    assert anon_client.post('/api/auth/login', content=chunks,
                            headers={'Content-Type': 'application/json'}).status_code == 413


def test_bcrypt_byte_boundary():
    auth.set_password('x' * 72)
    assert auth.verify_password('x' * 72)
    assert not auth.verify_password('x' * 72 + 'y')
    with pytest.raises(ValueError):
        auth.set_password('é' * 37)
    with auth._bcrypt_slot:
        assert not auth.verify_password('x' * 72)


def test_updater_rejects_ancestor_repository(tmp_path, monkeypatch):
    root = tmp_path / 'enclosing' / 'scanner'
    monkeypatch.setattr(updater, 'ROOT', root)
    monkeypatch.setattr(updater, '_git_available', lambda: True)
    monkeypatch.setattr(updater, '_git_sync', lambda *a: (0, str(root.parent), ''))
    assert not updater._is_repo_sync()
    monkeypatch.setattr(updater, '_git_sync', lambda *a: (0, str(root), ''))
    assert updater._is_repo_sync()


def test_group_report_omits_global_runs():
    group = db.create_group('Client')
    db.create_run(20, True)
    assert reports.gather_report_data(group_id=group, since='')['runs'] == []
    assert reports.gather_report_data(group_id=None, since='')['runs']


@pytest.mark.parametrize('email', ["a!#$&'*+/=?^`{|}~@example.com", 'a@例え.テスト'])
def test_unusual_email_is_redacted(email):
    assert email not in log_redact._redact('lookup failed: ' + email)


@pytest.mark.asyncio
async def test_one_shot_failure_never_persists(tmp_path, monkeypatch):
    class FailedClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def breached_account(self, email):
            raise scanner.HIBPError('failure involving ' + email)

    monkeypatch.setattr(scanner, 'HIBPClient', FailedClient)
    result = await scanner.run_scan(cfg={'hibp_api_key': 'synthetic'},
                                    emails=['private@example.com'], persist=False)
    assert result.run_id < 0
    assert result.errors
    assert 'private@example.com' not in str(result.errors)
    assert db.recent_runs() == []


def test_existing_credentials_get_restricted(monkeypatch):
    from backend import secrets_store
    auth.ensure_initial_token()
    secrets_store.encrypt('synthetic-secret')
    seen = []
    original = secrets_store._restrict
    def restrict(path):
        seen.append(path)
        original(path)
    monkeypatch.setattr(secrets_store, '_restrict', restrict)
    auth.ensure_initial_token()
    secrets_store._load_or_create_key()
    assert auth.TOKEN_FILE in seen
    assert secrets_store.KEY_PATH in seen


def test_permission_failure_prevents_secret_write(tmp_path, monkeypatch):
    from backend import secrets_store
    path = tmp_path / 'private' / 'secret'
    def fail(path):
        raise PermissionError('permissions unavailable')
    monkeypatch.setattr(secrets_store, '_restrict', fail)
    with pytest.raises(PermissionError):
        secrets_store.private_write(path, b'synthetic-secret')
    assert not path.exists()
