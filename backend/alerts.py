import asyncio
import html as html_mod
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Optional

import httpx

from . import log_redact, severity as sev_mod

log = logging.getLogger("dws.alerts")


def _level(f: dict) -> str:
    return (f.get("severity") or {}).get("level", "low")


def _by_sev_desc(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: -sev_mod.rank(_level(f)))


def _smtp_send(cfg: dict, msg: EmailMessage) -> None:
    host = cfg.get("smtp_host") or ""
    port = int(cfg.get("smtp_port") or 587)
    user = cfg.get("smtp_user") or ""
    password = cfg.get("smtp_pass") or ""
    if not host:
        raise RuntimeError("SMTP host not configured")
    ctx = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=30) as s:
            if user:
                s.login(user, password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=30) as s:
            s.ehlo()
            # Never downgrade authenticated mail or breach findings to plaintext.
            # An unsupported/failed STARTTLS handshake must abort before login.
            s.starttls(context=ctx)
            s.ehlo()
            if user:
                s.login(user, password)
            s.send_message(msg)


async def send_email(cfg: dict, subject: str, text: str,
                     html: Optional[str] = None) -> None:
    from_addr = cfg.get("from_addr") or cfg.get("smtp_user")
    to_addr = cfg.get("to_email")
    if not (from_addr and to_addr):
        raise RuntimeError("Email from/to not configured")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    await asyncio.to_thread(_smtp_send, cfg, msg)


def _format_webhook(kind: str, subject: str, text: str, fields: list[dict]) -> dict:
    if kind == "slack":
        blocks: list[dict] = [
            {"type": "header", "text": {"type": "plain_text", "text": subject}},
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        ]
        if fields:
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{f['name']}*\n{f['value']}"}
                    for f in fields[:10]
                ],
            })
        return {"text": subject, "blocks": blocks}
    if kind == "discord":
        return {
            "username": "DarkWebScanner",
            "embeds": [{
                "title": subject,
                "description": text,
                "color": 0xCC3333,
                "fields": [
                    {"name": f["name"], "value": f["value"][:1000], "inline": True}
                    for f in fields[:25]
                ],
            }],
        }
    return {"subject": subject, "text": text, "fields": fields}


async def send_webhook(cfg: dict, *, subject: str, text: str,
                       fields: Optional[list[dict]] = None) -> None:
    url = (cfg.get("webhook_url") or "").strip()
    if not url:
        raise RuntimeError("webhook URL not configured")
    # A generic webhook may carry its credential anywhere in its URL, not just
    # a query parameter. Register before HTTPX can log a request or exception.
    log_redact.register_secret(url)
    log_redact.register_secret(str(httpx.URL(url)))
    kind = (cfg.get("webhook_kind") or "generic").lower()
    if kind not in ("slack", "discord", "generic"):
        kind = "generic"
    payload = _format_webhook(kind, subject, text, fields or [])
    async with httpx.AsyncClient(timeout=20.0) as c:
        resp = await c.post(url, json=payload)
    if resp.status_code >= 400:
        raise RuntimeError(f"webhook HTTP {resp.status_code}: {resp.text[:200]}")


def _summary_counts(items: list[dict]) -> dict:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in items:
        out[_level(f)] = out.get(_level(f), 0) + 1
    return out


def _format_findings_text(breaches: list[dict], pastes: list[dict]) -> tuple[str, str]:
    breaches = _by_sev_desc(breaches)
    pastes = _by_sev_desc(pastes)

    lines = []
    if breaches:
        c = _summary_counts(breaches)
        lines.append(
            f"New breach findings ({len(breaches)}): "
            f"{c['critical']} critical, {c['high']} high, "
            f"{c['medium']} medium, {c['low']} low"
        )
        for f in breaches[:50]:
            classes = ", ".join(f.get("data_classes") or []) or "—"
            lines.append(
                f"  [{_level(f).upper()}] {f['email']} → "
                f"{f.get('title') or f['breach_name']} "
                f"({f.get('breach_date') or '?'}) [{classes}]"
            )
        if len(breaches) > 50:
            lines.append(f"  …and {len(breaches) - 50} more")

    if pastes:
        if lines:
            lines.append("")
        c = _summary_counts(pastes)
        lines.append(
            f"New paste findings ({len(pastes)}): "
            f"{c['high']} high, {c['medium']} medium, {c['low']} low"
        )
        for f in pastes[:25]:
            lines.append(
                f"  [{_level(f).upper()}] {f['email']} → "
                f"{f.get('source') or '?'} {f.get('title') or ''} "
                f"({f.get('paste_date') or '?'})"
            )
        if len(pastes) > 25:
            lines.append(f"  …and {len(pastes) - 25} more")

    text = "\n".join(lines) if lines else "No new findings."

    sev_color = {"critical": "#f85149", "high": "#d29922",
                 "medium": "#bb8009", "low": "#8b949e"}

    def esc(value) -> str:
        return html_mod.escape(str(value))

    def badge(level: str) -> str:
        return (f'<span style="display:inline-block;padding:1px 6px;border-radius:4px;'
                f'font-size:11px;background:{sev_color[level]};color:white;'
                f'margin-right:6px;text-transform:uppercase;">{level}</span>')

    html_parts: list[str] = []
    if breaches:
        c = _summary_counts(breaches)
        html_parts.append(
            f"<h3>New breach findings ({len(breaches)})</h3>"
            f"<p>{c['critical']} critical · {c['high']} high · "
            f"{c['medium']} medium · {c['low']} low</p><ul>"
        )
        for f in breaches[:50]:
            classes = ", ".join(f.get("data_classes") or []) or "—"
            html_parts.append(
                f"<li>{badge(_level(f))}<b>{esc(f['email'])}</b> → "
                f"{esc(f.get('title') or f['breach_name'])} "
                f"<i>({esc(f.get('breach_date') or '?')})</i><br>"
                f"<small>{esc(classes)}</small></li>"
            )
        html_parts.append("</ul>")
    if pastes:
        html_parts.append(f"<h3>New paste findings ({len(pastes)})</h3><ul>")
        for f in pastes[:25]:
            html_parts.append(
                f"<li>{badge(_level(f))}<b>{esc(f['email'])}</b> → "
                f"{esc(f.get('source') or '?')} {esc(f.get('title') or '')} "
                f"<i>({esc(f.get('paste_date') or '?')})</i></li>"
            )
        html_parts.append("</ul>")

    html = "".join(html_parts) if html_parts else "<p>No new findings.</p>"
    return text, html


async def alert_new_findings(cfg: dict, breaches: list[dict], pastes: list[dict]) -> dict:
    """Send alerts for new findings via configured channels. Returns per-channel status."""
    if not breaches and not pastes:
        return {"skipped": "no new findings"}

    counts = _summary_counts(breaches)
    severity_tag = ""
    if counts["critical"]:
        severity_tag = f"[CRITICAL×{counts['critical']}] "
    elif counts["high"]:
        severity_tag = f"[HIGH×{counts['high']}] "

    subject = (f"{severity_tag}DarkWebScanner: "
               f"{len(breaches)} new breach(es), {len(pastes)} new paste(s)")
    text, html = _format_findings_text(breaches, pastes)

    fields: list[dict] = []
    for f in _by_sev_desc(breaches)[:10]:
        fields.append({
            "name": f"[{_level(f).upper()}] {f.get('title') or f.get('breach_name', '?')}",
            "value": f"{f['email']} ({f.get('breach_date') or '?'})",
        })

    status: dict = {}
    if cfg.get("smtp_host") and cfg.get("to_email"):
        try:
            await send_email(cfg, subject, text, html)
            status["email"] = "sent"
        except Exception as e:
            log.exception("email alert failed")
            status["email"] = f"error: {e}"
    if cfg.get("webhook_url"):
        try:
            await send_webhook(cfg, subject=subject, text=text, fields=fields)
            status["webhook"] = "sent"
        except Exception as e:
            log.exception("webhook alert failed")
            status["webhook"] = f"error: {e}"
    return status or {"skipped": "no channels configured"}
