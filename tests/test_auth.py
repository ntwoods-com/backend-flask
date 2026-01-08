from __future__ import annotations


def test_auth_login_and_me(app_client):
    _app, client = app_client

    res = client.post(
        "/api/v1/auth/bootstrap",
        headers={"X-Bootstrap-Token": "test-bootstrap"},
        json={"email": "admin@example.com", "password": "password123", "role": "ADMIN"},
    )
    assert res.status_code == 201

    res = client.post(
        "/api/v1/auth/login", json={"email": "admin@example.com", "password": "password123"}
    )
    assert res.status_code == 200
    token = res.get_json()["data"]["access_token"]
    assert token

    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    me = res.get_json()["data"]
    assert me["email"] == "admin@example.com"
    assert me["role"] == "ADMIN"
