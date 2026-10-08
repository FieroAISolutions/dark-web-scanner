import asyncio
import html
import logging
import smtplib
import ssl
from email.message import EmailMessage
from unittest.mock import MagicMock

import httpx
import pytest

from backend import alerts, log_redact


@pytest.mark.parametrize("failure", [
    smtplib.SMTPNotSupportedError("STARTTLS unavailable"),
    ssl.SSLError("TLS handshake failed"),
])
@pytest.mark.parametrize("user", ["smtp-user", ""])
def test_smtp_tls_failure_never_authenticates_or_sends(monkeypatch, failure, user):
    server = MagicMock()
    server.__enter__.return_value = server
    server.starttls.side_effect = failure
    monkeypatch.setattr(alerts.smtplib, "SMTP", MagicMock(return_value=server))
    with pytest.raises(type(failure)):
        alerts._smtp_send({"smtp_host": "mail.invalid", "smtp_port": 587,
                           "smtp_user": user, "smtp_pass": "synthetic-password"},
                          EmailMessage())
    server.login.assert_not_called()
    server.send_message.assert_not_called()


@pytest.mark.parametrize("port", [465, 587])
def test_smtp_encrypted_delivery_still_works(monkeypatch, port):
    server = MagicMock()
    server.__enter__.return_value = server
    constructor = MagicMock(return_value=server)
    monkeypatch.setattr(alerts.smtplib, "SMTP_SSL" if port == 465 else "SMTP", constructor)
    message = EmailMessage()
    alerts._smtp_send({"smtp_host": "mail.invalid", "smtp_port": port,
                       "smtp_user": "synthetic-user", "smtp_pass": "synthetic-password"},
                      message)
    server.login.assert_called_once_with("synthetic-user", "synthetic-password")
    server.send_message.assert_called_once_with(message)
    if port == 587:
        assert [call[0] for call in server.method_calls] == [
            "ehlo", "starttls", "ehlo", "login", "send_message"]
    else:
        server.starttls.assert_not_called()
        assert isinstance(constructor.call_args.kwargs["context"], ssl.SSLContext)


@pytest.mark.parametrize("field", ["email", "title", "breach_date", "data_classes"])
def test_breach_email_escapes_external_fields(field):
    injection = '<img src="https://example.invalid/pixel">&'
    finding = {"email": "test@example.invalid", "breach_name": "example"}
    finding[field] = [injection] if field == "data_classes" else injection
    text, body = alerts._format_findings_text([finding], [])
    assert injection in text
    assert injection not in body
    assert html.escape(injection) in body


@pytest.mark.parametrize("field", ["email", "title", "source", "paste_date"])
def test_paste_email_escapes_external_fields(field):
    injection = '<a href="https://example.invalid">untrusted</a>'
    finding = {"email": "test@example.invalid", field: injection}
    _, body = alerts._format_findings_text([], [finding])
    assert injection not in body
    assert html.escape(injection) in body


@pytest.mark.parametrize("fail", [False, True])
def test_webhook_url_not_in_request_or_exception_logs(monkeypatch, caplog, fail):
    url = "https://generic.example.invalid/private/SYNTHETIC_WEBHOOK_CREDENTIAL"
    original_client = httpx.AsyncClient
    def respond(request):
        if fail:
            raise httpx.ConnectError("cannot connect to " + str(request.url), request=request)
        return httpx.Response(200)
    def client_factory(*args, **kwargs):
        return original_client(*args, **kwargs, transport=httpx.MockTransport(respond))
    monkeypatch.setattr(alerts.httpx, "AsyncClient", client_factory)
    log_redact.install()
    with caplog.at_level(logging.INFO):
        try:
            asyncio.run(alerts.send_webhook({"webhook_url": url},
                                          subject="synthetic", text="synthetic"))
        except httpx.ConnectError:
            logging.getLogger("dws").exception("synthetic webhook failure")
    assert url not in caplog.text
    assert "SYNTHETIC_WEBHOOK_CREDENTIAL" not in caplog.text
    assert "[redacted]" in caplog.text
