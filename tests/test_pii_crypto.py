from __future__ import annotations


def test_encrypt_decrypt_aesgcm_roundtrip():
    from pii import decrypt_pii, encrypt_pii

    key = "test-key-material"
    aad = "test:aad"
    plaintext = "Hello PII"

    ct = encrypt_pii(plaintext, key=key, aad=aad)
    assert ct.startswith("v1:")
    assert decrypt_pii(ct, key=key, aad=aad) == plaintext


def test_encrypt_decrypt_fallback_roundtrip(monkeypatch):
    import pii

    monkeypatch.setattr(pii, "_try_get_aesgcm", lambda: None)

    key = "test-key-material"
    aad = "test:aad"
    plaintext = "Hello PII"

    ct = pii.encrypt_pii(plaintext, key=key, aad=aad)
    assert ct.startswith("v0:")
    assert pii.decrypt_pii(ct, key=key, aad=aad) == plaintext
    assert pii.decrypt_pii(ct, key=key, aad="wrong:aad") == ""


def test_parse_name_mobile_from_cv_filename():
    from schema import _parse_name_mobile_from_cv_filename

    name, mobile = _parse_name_mobile_from_cv_filename("Aakash_Kumar_9001294795_Apna.pdf")
    assert name == "Aakash Kumar"
    assert mobile == "9001294795"

