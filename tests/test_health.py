from __future__ import annotations


def test_health_ok(app_client):
    _app, client = app_client
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["db"] == "ok"
    assert "time" in data
    assert "version" in data


def test_version(app_client):
    _app, client = app_client
    res = client.get("/version")
    assert res.status_code == 200
    data = res.get_json()
    assert "version" in data
    assert "env" in data
    assert "time" in data
