from backend import config, db, secrets_store


def test_get_public_masks_secrets():
    config.update({
        "hibp_api_key": "very-secret",
        "smtp_pass": "pass-1234",
        "webhook_url": "https://hooks.example.com/abc",
    })
    pub = config.get_public()
    assert "hibp_api_key" not in pub
    assert "smtp_pass" not in pub
    assert "webhook_url" not in pub
    assert "admin_token_hash" not in pub
    assert pub["hibp_api_key_set"] is True
    assert pub["smtp_pass_set"] is True
    assert pub["webhook_url_set"] is True


def test_get_full_decrypts_secrets():
    config.update({"hibp_api_key": "abc-123"})
    full = config.get_full()
    assert full["hibp_api_key"] == "abc-123"

    # And the value at rest is encrypted
    raw = db.get_config_row()
    assert secrets_store.is_encrypted(raw["hibp_api_key"])


def test_blank_secret_preserves_existing():
    config.update({"hibp_api_key": "first"})
    config.update({"hibp_api_key": "", "interval_hours": 12})
    full = config.get_full()
    assert full["hibp_api_key"] == "first"
    assert full["interval_hours"] == 12


def test_normalizes_booleans_and_ints():
    config.update({
        "enabled": True, "interval_hours": "8",
        "alert_on_new": False, "include_pastes": True,
        "smtp_port": "465", "hibp_rpm": "50",
    })
    full = config.get_full()
    assert full["enabled"] == 1
    assert full["alert_on_new"] == 0
    assert full["include_pastes"] == 1
    assert full["interval_hours"] == 8
    assert full["smtp_port"] == 465
    assert full["hibp_rpm"] == 50


def test_clamps_minimum_interval_and_rpm():
    config.update({"interval_hours": 0, "hibp_rpm": 0})
    full = config.get_full()
    assert full["interval_hours"] == 1
    assert full["hibp_rpm"] == 1


def test_invalid_webhook_kind_falls_back_to_generic():
    config.update({"webhook_kind": "bogus"})
    assert config.get_full()["webhook_kind"] == "generic"


def test_unknown_fields_ignored():
    config.update({"hibp_api_key": "k", "evil_field": "x"})
    full = config.get_full()
    assert "evil_field" not in full
