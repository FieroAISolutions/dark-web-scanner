"""
Self-contained HTML report renderer. Designed to be browser-printable —
the report includes its own inline stylesheet so it's a single file an
operator can save / email / print to PDF without server help.

Scope is always one group + a since-date. Contents:
  • Header: scan-org / client name (group), report period, generated-at
  • Summary cards: monitored count, severity counts, total findings
  • Findings table grouped by severity, then by email
  • Pastes table
  • Scan-runs table for the period
"""

from __future__ import annotations

import html
from datetime import datetime, timedelta, timezone
from typing import Optional

from . import db, severity as sev_mod


# ── Date helpers ──────────────────────────────────────────────────────────────

def parse_since(value: Optional[str]) -> str:
    """Validate / normalise an ISO datetime to UTC. Returns SQLite-friendly text."""
    if not value:
        return ""
    try:
        # Accept date-only or datetime in any reasonable form
        if "T" in value or " " in value:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(value + "T00:00:00+00:00")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError as e:
        raise ValueError(f"invalid date '{value}': {e}") from e


def default_since(days: int = 30) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


# ── Data assembly ─────────────────────────────────────────────────────────────

def gather_report_data(group_id: Optional[int], since: str) -> dict:
    """Pull everything a report needs for one group + date range."""
    group = db.get_group(group_id) if group_id is not None else None
    findings = db.list_findings(limit=10_000, only_new_since=since or None,
                                group_id=group_id)
    pastes_all = db.list_pastes(limit=10_000, group_id=group_id)
    if since:
        pastes = [p for p in pastes_all if (p.get("first_seen_at") or "") >= since]
    else:
        pastes = pastes_all
    monitored = db.list_emails(group_id=group_id)
    sev_counts = db.severity_counts(group_id=group_id)

    runs = db.recent_runs(limit=100)
    if since:
        runs = [r for r in runs if (r.get("started_at") or "") >= since]

    return {
        "group": group,
        "findings": findings,
        "pastes": pastes,
        "monitored": monitored,
        "severity_counts": sev_counts,
        "runs": runs,
        "since": since,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


# ── HTML rendering ────────────────────────────────────────────────────────────

_CSS = """
:root {
  --bg: #ffffff; --text: #111; --muted: #666; --border: #ddd; --panel: #f6f8fa;
  --crit: #b91c1c; --high: #b45309; --med: #92400e; --low: #525252;
}
* { box-sizing: border-box; }
body {
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  margin: 24px; color: var(--text); background: var(--bg); max-width: 1100px;
}
h1 { margin: 0 0 4px; font-size: 22px; }
h2 { margin: 24px 0 8px; font-size: 16px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }
h3 { margin: 16px 0 6px; font-size: 14px; color: var(--muted); }
.meta { color: var(--muted); font-size: 13px; margin-bottom: 16px; }
.cards { display: grid; gap: 8px; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); margin-bottom: 16px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; }
.card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
.card .value { font-size: 22px; font-weight: 600; margin-top: 2px; }
.card.crit .value { color: var(--crit); }
.card.high .value { color: var(--high); }
.card.med .value  { color: var(--med); }
.card.low .value  { color: var(--low); }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-bottom: 16px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { background: var(--panel); font-weight: 600; }
.sev { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px; font-weight: 700; text-transform: uppercase; color: white; }
.sev.crit { background: var(--crit); } .sev.high { background: var(--high); }
.sev.med  { background: var(--med); }  .sev.low  { background: var(--low); }
.dc { display: inline-block; background: #eef; color: #335; border: 1px solid #ccd; border-radius: 3px; padding: 0 5px; font-size: 11px; margin: 1px 2px 1px 0; }
.empty { color: var(--muted); font-style: italic; }
.print-only { display: none; }
@media print {
  body { margin: 12mm; max-width: none; }
  .no-print { display: none !important; }
  .print-only { display: initial; }
  table { page-break-inside: auto; } tr { page-break-inside: avoid; page-break-after: auto; }
  thead { display: table-header-group; }
}
"""


def _esc(s) -> str:
    return html.escape("" if s is None else str(s))


def _sev_label(level: str) -> str:
    cls = {"critical": "crit", "high": "high", "medium": "med", "low": "low"}.get(level, "low")
    return f'<span class="sev {cls}">{html.escape(level)}</span>'


def _sev_class(level: str) -> str:
    return {"critical": "crit", "high": "high", "medium": "med", "low": "low"}.get(level, "low")


def render(data: dict) -> str:
    g = data["group"]
    title = (g["name"] if g else "All groups") + " — DarkWebScanner report"
    sc = data["severity_counts"]
    findings = data["findings"]
    pastes = data["pastes"]
    runs = data["runs"]
    monitored = data["monitored"]

    period = ("Since " + data["since"]) if data["since"] else "All time"
    desc = g.get("description") if g else ""

    # Group findings by severity for the report body
    by_level: dict[str, list[dict]] = {"critical": [], "high": [], "medium": [], "low": []}
    for f in findings:
        by_level[(f.get("severity") or {}).get("level", "low")].append(f)

    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>{_esc(title)}</title>",
        f"<style>{_CSS}</style></head><body>",
        '<div class="no-print" style="text-align:right;margin-bottom:8px;">'
        '<button onclick="window.print()" style="padding:6px 14px;">🖨 Print / Save as PDF</button>'
        "</div>",
        f"<h1>{_esc(title)}</h1>",
        f'<div class="meta">{_esc(period)} · Generated {_esc(data["generated_at"])}'
        + (f' · <i>{_esc(desc)}</i>' if desc else "") + "</div>",
        # Summary cards
        '<div class="cards">',
        f'<div class="card"><div class="label">Monitored</div><div class="value">{len(monitored)}</div></div>',
        f'<div class="card crit"><div class="label">Critical</div><div class="value">{sc["critical"]}</div></div>',
        f'<div class="card high"><div class="label">High</div><div class="value">{sc["high"]}</div></div>',
        f'<div class="card med"><div class="label">Medium</div><div class="value">{sc["medium"]}</div></div>',
        f'<div class="card low"><div class="label">Low</div><div class="value">{sc["low"]}</div></div>',
        f'<div class="card"><div class="label">Pastes</div><div class="value">{len(pastes)}</div></div>',
        "</div>",
    ]

    # Findings table
    parts.append("<h2>Breach findings</h2>")
    if not findings:
        parts.append('<p class="empty">No breach findings in this period.</p>')
    else:
        for level in ("critical", "high", "medium", "low"):
            block = by_level[level]
            if not block:
                continue
            parts.append(f"<h3>{level.title()} — {len(block)} finding(s)</h3>")
            parts.append("<table><thead><tr>"
                         "<th>Severity</th><th>Email</th><th>Breach</th>"
                         "<th>Date</th><th>Pwn count</th>"
                         "<th>Data classes</th><th>First seen</th></tr></thead><tbody>")
            for f in block:
                dc = "".join(f'<span class="dc">{_esc(c)}</span>'
                             for c in (f.get("data_classes") or []))
                parts.append(
                    "<tr>"
                    f"<td>{_sev_label((f.get('severity') or {}).get('level','low'))}</td>"
                    f"<td>{_esc(f.get('email'))}</td>"
                    f"<td>{_esc(f.get('title') or f.get('breach_name'))}<br>"
                    f"<span style='color:var(--muted)'>{_esc(f.get('domain') or '')}</span></td>"
                    f"<td>{_esc(f.get('breach_date') or '—')}</td>"
                    f"<td>{(f.get('pwn_count') or 0):,}</td>"
                    f"<td>{dc or '—'}</td>"
                    f"<td>{_esc(f.get('first_seen_at') or '—')}</td>"
                    "</tr>"
                )
            parts.append("</tbody></table>")

    # Pastes table
    parts.append("<h2>Paste mentions</h2>")
    if not pastes:
        parts.append('<p class="empty">No paste mentions in this period.</p>')
    else:
        parts.append("<table><thead><tr>"
                     "<th>Severity</th><th>Email</th><th>Source</th>"
                     "<th>Title</th><th>Paste date</th>"
                     "<th>Addresses in paste</th><th>First seen</th></tr></thead><tbody>")
        for p in pastes:
            parts.append(
                "<tr>"
                f"<td>{_sev_label((p.get('severity') or {}).get('level','low'))}</td>"
                f"<td>{_esc(p.get('email'))}</td>"
                f"<td>{_esc(p.get('source') or '?')}</td>"
                f"<td>{_esc(p.get('title') or '—')}</td>"
                f"<td>{_esc(p.get('paste_date') or '—')}</td>"
                f"<td>{(p.get('email_count') or 0):,}</td>"
                f"<td>{_esc(p.get('first_seen_at') or '—')}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    # Monitored emails (for context)
    parts.append(f"<h2>Monitored addresses ({len(monitored)})</h2>")
    if not monitored:
        parts.append('<p class="empty">No addresses currently monitored in this scope.</p>')
    else:
        parts.append("<table><thead><tr>"
                     "<th>Email</th><th>Group</th><th>Added</th>"
                     "<th>Breaches</th><th>Pastes</th><th>Last seen</th></tr></thead><tbody>")
        for e in monitored:
            parts.append(
                "<tr>"
                f"<td>{_esc(e.get('email'))}</td>"
                f"<td>{_esc(e.get('group_name') or '—')}</td>"
                f"<td>{_esc(e.get('added_at') or '—')}</td>"
                f"<td>{e.get('breach_count') or 0}</td>"
                f"<td>{e.get('paste_count') or 0}</td>"
                f"<td>{_esc(e.get('last_breach_at') or '—')}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    # Scan runs in period
    parts.append(f"<h2>Scan runs in period ({len(runs)})</h2>")
    if not runs:
        parts.append('<p class="empty">No scans in this period.</p>')
    else:
        parts.append("<table><thead><tr>"
                     "<th>Started</th><th>Finished</th><th>Emails</th>"
                     "<th>New breaches</th><th>New pastes</th><th>Status</th></tr></thead><tbody>")
        for r in runs:
            parts.append(
                "<tr>"
                f"<td>{_esc(r.get('started_at'))}</td>"
                f"<td>{_esc(r.get('finished_at') or '—')}</td>"
                f"<td>{r.get('email_count') or 0}</td>"
                f"<td>{r.get('new_breaches') or 0}</td>"
                f"<td>{r.get('new_pastes') or 0}</td>"
                f"<td>{_esc(r.get('status'))}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    parts.append('<div class="meta print-only">DarkWebScanner — '
                 f'report generated {_esc(data["generated_at"])}</div>')
    parts.append("</body></html>")
    return "".join(parts)
