from . import db, log_redact, secrets_store


SECRET_FIELDS = {"hibp_api_key", "smtp_pass", "webhook_url", "github_token"}
ALLOWED_FIELDS = {
    "enabled", "interval_hours", "hibp_api_key", "hibp_rpm", "include_pastes",
    "alert_on_new", "smtp_host", "smtp_port", "smtp_user", "smtp_pass",
    "from_addr", "to_email", "webhook_url", "webhook_kind", "user_agent",
    "github_token",
}
WEBHOOK_KINDS = {"slack", "discord", "generic", ""}


def get_full() -> dict:
    """Internal use — secrets are decrypted from at-rest ciphertext."""
    row = dict(db.get_config_row())
    for field in SECRET_FIELDS:
        if field in row:
            row[field] = secrets_store.decrypt(row[field] or "")
            log_redact.register_secret(row[field])
    return row


def get_public() -> dict:
    """For the UI — secrets replaced with *_set boolean flags."""
    full = get_full()
    hidden = SECRET_FIELDS | {"admin_token_hash", "admin_password_hash"}
    out = {k: v for k, v in full.items() if k not in hidden}
    out["enabled"] = bool(full["enabled"])
    out["alert_on_new"] = bool(full["alert_on_new"])
    out["include_pastes"] = bool(full["include_pastes"])
    out["hibp_api_key_set"] = bool(full["hibp_api_key"])
    out["smtp_pass_set"] = bool(full["smtp_pass"])
    out["webhook_url_set"] = bool(full["webhook_url"])
    out["github_token_set"] = bool(full.get("github_token"))
    return out


def update(payload: dict) -> dict:
    """Apply partial config update. Empty-string secrets preserve existing values."""
    fields: dict = {}
    for key, value in payload.items():
        if key not in ALLOWED_FIELDS:
            continue
        if key in SECRET_FIELDS and (value is None or value == ""):
            continue  # preserve existing secret
        if key in ("enabled", "alert_on_new", "include_pastes"):
            value = 1 if bool(value) else 0
        if key in ("interval_hours", "smtp_port", "hibp_rpm"):
            try:
                value = int(value)
            except (TypeError, ValueError):
                continue
        if key == "webhook_kind" and value not in WEBHOOK_KINDS:
            value = "generic"
        if key == "interval_hours" and value < 1:
            value = 1
        if key == "hibp_rpm" and value < 1:
            value = 1
        if key in SECRET_FIELDS and isinstance(value, str):
            value = secrets_store.encrypt(value)
        fields[key] = value
    db.update_config(fields)
    return get_public()


def migrate_legacy_secrets() -> int:
    """Encrypt any plaintext secrets left in the DB from previous versions."""
    return secrets_store.migrate_legacy(
        db.get_config_row, db.update_config, SECRET_FIELDS,
    )
