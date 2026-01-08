from __future__ import annotations

import os
from datetime import datetime, timezone

from db import SessionLocal
from models import Candidate, CandidateTest, SLAConfig, User
from pii import hash_email, hash_name, hash_phone, mask_email, mask_name, mask_phone
from sla import compute_sla
from utils import iso_utc_now


def _api(client, *, action: str, token: str | None = None, data: dict | None = None):
    payload = {"action": action, "token": token or "", "data": data or {}}
    return client.post("/api", json=payload)


def _seed_user(*, user_id: str, email: str, role: str):
    pepper = os.getenv("PEPPER", "test-pepper")
    email_h = hash_email(email, pepper)
    name_raw = role.title()
    name_h = hash_name(name_raw, pepper)
    name_m = mask_name(name_raw)
    now = iso_utc_now()

    db = SessionLocal()
    try:
        db.add(
            User(
                userId=user_id,
                email=email_h,
                fullName=name_m,
                email_hash=email_h,
                name_hash=name_h,
                email_masked=mask_email(email),
                name_masked=name_m,
                role=role,
                status="ACTIVE",
                lastLoginAt="",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.commit()
    finally:
        db.close()


def _login(client, email: str) -> str:
    resp = _api(client, action="LOGIN_EXCHANGE", data={"idToken": f"TEST:{email}"})
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["ok"] is True
    token = body["data"]["sessionToken"]
    assert isinstance(token, str) and token
    return token


def test_candidate_test_assignment_isolation(app_client):
    _app, client = app_client

    # Two ACCOUNTS users.
    _seed_user(user_id="U-A", email="a@example.com", role="ACCOUNTS")
    _seed_user(user_id="U-B", email="b@example.com", role="ACCOUNTS")

    token_a = _login(client, "a@example.com")
    token_b = _login(client, "b@example.com")

    # Candidate + required test assigned to user A.
    pepper = os.getenv("PEPPER", "test-pepper")
    now = iso_utc_now()
    cand_id = "CND-TEST-1"
    req_id = "REQ-TEST-1"

    db = SessionLocal()
    try:
        db.add(
            Candidate(
                candidateId=cand_id,
                requirementId=req_id,
                candidateName=mask_name("Candidate One"),
                jobRole="ACCOUNTS",
                mobile=mask_phone("9876543210"),
                name_hash=hash_name("Candidate One", pepper),
                mobile_hash=hash_phone("9876543210", pepper),
                name_masked=mask_name("Candidate One"),
                mobile_masked=mask_phone("9876543210"),
                source="",
                cvFileId="",
                cvFileName="",
                status="WALKIN_SCHEDULED",
                createdAt=now,
                createdBy="TEST",
                updatedAt=now,
                updatedBy="TEST",
            )
        )
        db.add(
            CandidateTest(
                candidateId=cand_id,
                requirementId=req_id,
                testKey="TALLY",
                isRequired=True,
                status="PENDING",
                fillOwnerUserId="U-A",
                marksJson="",
                marksNumber=None,
                filledBy="",
                filledAt="",
                reviewedBy="",
                reviewedAt="",
                remarks="",
                createdAt=now,
                updatedAt=now,
            )
        )
        db.commit()
    finally:
        db.close()

    # A sees it, B doesn't.
    res_a = _api(client, action="TESTS_QUEUE_LIST", token=token_a, data={"mode": "FILL"}).get_json()
    assert res_a["ok"] is True
    assert len(res_a["data"]["items"]) == 1

    res_b = _api(client, action="TESTS_QUEUE_LIST", token=token_b, data={"mode": "FILL"}).get_json()
    assert res_b["ok"] is True
    assert len(res_b["data"]["items"]) == 0

    # B cannot submit (403).
    resp = _api(
        client,
        action="CANDIDATE_TEST_SUBMIT",
        token=token_b,
        data={"candidateId": cand_id, "requirementId": req_id, "testKey": "TALLY", "marks": 5, "remarks": ""},
    )
    body = resp.get_json()
    assert resp.status_code == 403
    assert body["ok"] is False
    assert body["error"]["code"] == "FORBIDDEN"

    # A can submit.
    resp2 = _api(
        client,
        action="CANDIDATE_TEST_SUBMIT",
        token=token_a,
        data={"candidateId": cand_id, "requirementId": req_id, "testKey": "TALLY", "marks": 5, "remarks": ""},
    )
    body2 = resp2.get_json()
    assert resp2.status_code == 200
    assert body2["ok"] is True


def test_sla_overdue_logic(app_client):
    _app, _client = app_client
    db = SessionLocal()
    try:
        db.merge(SLAConfig(stepName="PRECALL", plannedMinutes=1, enabled=True, updatedAt=iso_utc_now(), updatedBy="TEST"))
        db.commit()

        start = "2026-01-01T00:00:00Z"
        now_dt = datetime(2026, 1, 1, 0, 2, 0, tzinfo=timezone.utc)
        out = compute_sla(db, step_name="PRECALL", start_ts=start, app_timezone="UTC", now=now_dt)
        assert out["plannedMinutes"] == 1
        assert out["status"] == "OVERDUE"
        assert isinstance(out["deadlineAt"], str) and out["deadlineAt"]
    finally:
        db.close()


def test_training_multi_video_crud(app_client):
    _app, client = app_client

    # Admin user for template CRUD.
    _seed_user(user_id="U-ADMIN", email="admin@example.com", role="ADMIN")
    token = _login(client, "admin@example.com")

    # Create template with two videos.
    resp = _api(
        client,
        action="TRAINING_MASTER_UPSERT",
        token=token,
        data={
            "name": "CRM",
            "department": "Accounts",
            "description": "Test training",
            "video_links": ["https://example.com/v1", "https://example.com/v2"],
            "documentsLines": "",
        },
    )
    body = resp.get_json()
    assert body["ok"] is True
    training_id = body["data"]["training_id"]

    # List templates includes video_links.
    resp2 = _api(client, action="TRAINING_MASTER_LIST", token=token, data={})
    body2 = resp2.get_json()
    assert body2["ok"] is True
    tpl = next((x for x in body2["data"]["items"] if x.get("training_id") == training_id), None)
    assert tpl is not None
    assert tpl.get("video_link") == "https://example.com/v1"
    assert tpl.get("video_links") == ["https://example.com/v1", "https://example.com/v2"]

    # Assign to a candidate_id (no need for Candidate row for admin flow).
    resp3 = _api(
        client,
        action="TRAINING_ASSIGN",
        token=token,
        data={
            "candidate_id": "CND-X",
            "training_id": training_id,
            "due_date": "2099-01-01T00:00:00Z",
        },
    )
    body3 = resp3.get_json()
    assert body3["ok"] is True

    # Training list returns video_links.
    resp4 = _api(client, action="TRAINING_LIST", token=token, data={"candidate_id": "CND-X"})
    body4 = resp4.get_json()
    assert body4["ok"] is True
    assert len(body4["data"]["items"]) == 1
    item = body4["data"]["items"][0]
    assert item.get("video_link") == "https://example.com/v1"
    assert item.get("video_links") == ["https://example.com/v1", "https://example.com/v2"]

