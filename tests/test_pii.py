import hashlib
import hmac

from pii import (
    hash_email,
    hash_name,
    hash_phone,
    normalize_email,
    normalize_name,
    normalize_phone,
)


def test_normalization():
    assert normalize_email("  Test@Example.COM  ") == "test@example.com"
    assert normalize_name("  Alice   Bob  ") == "alice bob"
    assert normalize_phone("+91 98765-43210") == "9876543210"
    assert normalize_phone("91-9876543210") == "9876543210"


def test_deterministic_hmac_sha256():
    pepper = "unit-test-pepper"
    email = "Test@Example.com"
    expected = hmac.new(pepper.encode("utf-8"), normalize_email(email).encode("utf-8"), hashlib.sha256).hexdigest()
    assert hash_email(email, pepper) == expected

    name = " Alice  Bob "
    expected_name = hmac.new(pepper.encode("utf-8"), normalize_name(name).encode("utf-8"), hashlib.sha256).hexdigest()
    assert hash_name(name, pepper) == expected_name

    phone = "+91 98765 43210"
    expected_phone = hmac.new(pepper.encode("utf-8"), normalize_phone(phone).encode("utf-8"), hashlib.sha256).hexdigest()
    assert hash_phone(phone, pepper) == expected_phone

