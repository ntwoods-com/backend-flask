from __future__ import annotations

from datetime import datetime, timezone


def _bootstrap_and_login(client) -> str:
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
    return res.get_json()["data"]["access_token"]


def test_reports_summary(app_client):
    app, client = app_client
    token = _bootstrap_and_login(client)

    db = app.extensions["mongo_db"]
    db.requirements.insert_many(
        [
            {
                "requirementId": "R1",
                "status": "OPEN",
                "createdAt": datetime(2026, 1, 1, tzinfo=timezone.utc),
            },
            {
                "requirementId": "R2",
                "status": "CLOSED",
                "createdAt": datetime(2026, 1, 2, tzinfo=timezone.utc),
            },
        ]
    )
    db.candidates.insert_many(
        [
            {
                "candidateId": "C1",
                "requirementId": "R1",
                "stage": "APPLIED",
                "createdAt": datetime(2026, 1, 1, tzinfo=timezone.utc),
            },
            {
                "candidateId": "C2",
                "requirementId": "R1",
                "stage": "JOINED",
                "createdAt": datetime(2026, 1, 2, tzinfo=timezone.utc),
            },
            {
                "candidateId": "C3",
                "requirementId": "R2",
                "stage": "APPLIED",
                "createdAt": datetime(2026, 1, 2, tzinfo=timezone.utc),
            },
        ]
    )

    res = client.get(
        "/api/v1/reports/summary?from=2026-01-01&to=2026-01-02",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    payload = res.get_json()
    assert payload["success"] is True
    data = payload["data"]
    assert data["requirements"]["total"] == 2
    assert data["candidates"]["total"] == 3
