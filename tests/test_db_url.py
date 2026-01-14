from db import _normalize_database_url


def test_normalize_database_url_converts_libpq_conninfo():
    raw = "user=postgres.myref password=[pass] host=aws.pooler.supabase.com port=6543 dbname=postgres"
    normalized = _normalize_database_url(raw)

    assert normalized.startswith("postgresql+psycopg://postgres.myref:")
    assert "%5Bpass%5D" in normalized
    assert "@aws.pooler.supabase.com:6543/postgres" in normalized


def test_normalize_database_url_converts_libpq_conninfo_without_spaces():
    raw = "user=postgres.myrefpassword=[pass]host=aws.pooler.supabase.comport=6543dbname=postgres"
    normalized = _normalize_database_url(raw)

    assert normalized.startswith("postgresql+psycopg://postgres.myref:")
    assert "%5Bpass%5D" in normalized
    assert "@aws.pooler.supabase.com:6543/postgres" in normalized


def test_normalize_database_url_strips_leading_key_prefix_before_url():
    raw = "user=postgresql://postgres.myref:[pass]@aws.pooler.supabase.com:6543/postgres"
    normalized = _normalize_database_url(raw)

    assert normalized.startswith("postgresql+psycopg://postgres.myref:")
    assert normalized.endswith("@aws.pooler.supabase.com:6543/postgres")
