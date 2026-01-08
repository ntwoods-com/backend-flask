import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


@pytest.fixture()
def app_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENV", "testing")
    monkeypatch.setenv("MONGODB_URI", "mongomock://localhost")
    monkeypatch.setenv("DB_NAME", "hrms_test")
    monkeypatch.setenv("JWT_SECRET", "test-secret")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "test-bootstrap")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")

    from app import create_app
    from app.db import reset_client_for_tests

    reset_client_for_tests()
    app = create_app()
    app.testing = True

    with app.test_client() as client:
        yield app, client
