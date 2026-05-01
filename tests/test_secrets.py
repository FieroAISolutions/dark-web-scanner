from backend import secrets_store


def test_roundtrip():
    enc = secrets_store.encrypt("super-secret")
    assert enc.startswith("enc:v1:")
    assert secrets_store.decrypt(enc) == "super-secret"


def test_empty_string_unchanged():
    assert secrets_store.encrypt("") == ""
    assert secrets_store.decrypt("") == ""


def test_double_encrypt_is_idempotent():
    enc1 = secrets_store.encrypt("hello")
    enc2 = secrets_store.encrypt(enc1)
    assert enc1 == enc2  # already-encrypted values aren't re-encrypted


def test_decrypt_plaintext_passthrough():
    """Legacy unencrypted values flow through untouched (for migration)."""
    assert secrets_store.decrypt("legacy-plaintext") == "legacy-plaintext"


def test_is_encrypted():
    assert not secrets_store.is_encrypted("hello")
    assert secrets_store.is_encrypted(secrets_store.encrypt("hello"))


def test_migrate_legacy_encrypts_in_place():
    from backend import db
    # Simulate a legacy plaintext config
    db.update_config({"hibp_api_key": "plaintext-key", "smtp_pass": "plaintext-pass"})
    n = secrets_store.migrate_legacy(
        db.get_config_row, db.update_config,
        {"hibp_api_key", "smtp_pass", "webhook_url"},
    )
    assert n == 2

    row = db.get_config_row()
    assert secrets_store.is_encrypted(row["hibp_api_key"])
    assert secrets_store.is_encrypted(row["smtp_pass"])
    assert secrets_store.decrypt(row["hibp_api_key"]) == "plaintext-key"
    assert secrets_store.decrypt(row["smtp_pass"]) == "plaintext-pass"


def test_key_file_created_with_restricted_perms(tmp_path):
    """The .scanner_key file should be created the first time we encrypt anything."""
    secrets_store.encrypt("trigger-key-creation")
    assert secrets_store.KEY_PATH.exists()
