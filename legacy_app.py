from __future__ import annotations

import glob
import json
import logging
import mimetypes
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from dotenv import load_dotenv
from flask import Blueprint, Flask, current_app, g, request, send_file
from flask_cors import CORS
from zoneinfo import ZoneInfo

from actions import dispatch
from auth import assert_permission, is_public_action, role_or_public, validate_session_token
from config import Config
from db import SessionLocal, init_engine
from models import AuditLog, Permission, Role, SLAConfig, TestMaster
from utils import ApiError, AuthContext, SimpleRateLimiter, err, iso_utc_now, now_monotonic, ok, parse_json_body, redact_for_audit


rest_api = Blueprint("rest_api", __name__)


def _rest_token() -> str:
    authz = str(request.headers.get("Authorization") or "").strip()
    if authz.lower().startswith("bearer "):
        return authz.split(" ", 1)[1].strip()
    return (
        str(request.headers.get("X-Session-Token") or "").strip()
        or str(request.args.get("token") or "").strip()
        or str((request.get_json(silent=True) or {}).get("token") or "").strip()
    )


def _rest_handle(action: str, data: dict, *, allow_internal: bool = False):
    from db import SessionLocal

    if SessionLocal is None:
        raise RuntimeError("DB not initialized")

    cfg = current_app.config["CFG"]
    token = _rest_token()
    action_u = str(action or "").upper().strip()

    db = None
    auth_ctx = None
    try:
        db = SessionLocal()

        if allow_internal:
            internal = str(request.headers.get("X-Internal-Token") or "").strip()
            internal_expected = str(os.getenv("INTERNAL_CRON_TOKEN", "") or "").strip()
            if internal_expected and internal and internal == internal_expected:
                auth_ctx = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="ADMIN", expiresAt="")
            else:
                auth_ctx = validate_session_token(db, token)
        else:
            auth_ctx = validate_session_token(db, token)

        if not auth_ctx or not auth_ctx.valid:
            raise ApiError("AUTH_INVALID", "Invalid or expired session")

        role = role_or_public(auth_ctx)
        assert_permission(db, role, action_u)

        out = dispatch(action_u, data or {}, auth_ctx, db, cfg)

        try:
            db.add(
                AuditLog(
                    logId=f"LOG-{os.urandom(16).hex()}",
                    entityType="API",
                    entityId=str(auth_ctx.userId or auth_ctx.email or ""),
                    action=action_u,
                    fromState="",
                    toState="",
                    stageTag="API_CALL_REST",
                    remark="",
                    actorUserId=str(auth_ctx.userId),
                    actorRole=str(auth_ctx.role),
                    at=iso_utc_now(),
                    metaJson=json.dumps({"data": redact_for_audit(data or {})}),
                )
            )
        except Exception:
            pass

        db.commit()
        return ok(out)[0]
    except ApiError as e:
        if db is not None:
            db.rollback()
        _write_error_audit(cfg, action_u, auth_ctx, data, e)
        return err(e.code, e.message, http_status=e.http_status)[0], e.http_status
    except Exception:
        if db is not None:
            db.rollback()
        api_err = ApiError("INTERNAL", "Unexpected error")
        _write_error_audit(cfg, action_u, auth_ctx, data, api_err)
        logging.getLogger("api").exception("rest action=%s", action_u)
        return err(api_err.code, api_err.message)[0]
    finally:
        if db is not None:
            db.close()


def _maybe_start_internal_scheduler(cfg: Config):
    """
    Daily scheduler (Asia/Kolkata) for lightweight maintenance jobs.

    Production recommendation: run a single instance via cron/Task Scheduler calling
    `POST /api/jobs/auto-reschedule-no-show` with `X-Internal-Token` = `INTERNAL_CRON_TOKEN`.

    For simple deployments you can enable the in-process scheduler:
    - ENABLE_SCHEDULER=1
    - SCHEDULER_RESCHEDULE_HOUR=0
    - SCHEDULER_RESCHEDULE_MINUTE=10
    """

    if str(os.getenv("ENABLE_SCHEDULER", "0") or "").strip() != "1":
        return

    try:
        hour = int(os.getenv("SCHEDULER_RESCHEDULE_HOUR", "0"))
        minute = int(os.getenv("SCHEDULER_RESCHEDULE_MINUTE", "10"))
    except Exception:
        hour, minute = 0, 10

    hour = max(0, min(23, hour))
    minute = max(0, min(59, minute))

    try:
        tz = ZoneInfo(cfg.APP_TIMEZONE)
    except Exception:
        tz = timezone.utc

    def _loop():
        from db import SessionLocal

        while True:
            now_local = datetime.now(tz)
            next_run = datetime(now_local.year, now_local.month, now_local.day, hour, minute, 0, tzinfo=tz)
            if next_run <= now_local:
                next_run = next_run + timedelta(days=1)
            delay = max(1.0, (next_run - now_local).total_seconds())
            time.sleep(delay)

            db = None
            try:
                if SessionLocal is None:
                    continue
                db = SessionLocal()
                system = AuthContext(valid=True, userId="SYSTEM", email="SYSTEM", role="ADMIN", expiresAt="")
                auto_res = dispatch("AUTO_RESCHEDULE_NO_SHOW", {"dryRun": False}, system, db, cfg)
                db.commit()
                logging.getLogger("scheduler").info("AUTO_RESCHEDULE_NO_SHOW ok=%s", bool(auto_res and auto_res.get("ok")))
            except Exception:
                if db is not None:
                    db.rollback()
                logging.getLogger("scheduler").exception("AUTO_RESCHEDULE_NO_SHOW failed")
            finally:
                if db is not None:
                    db.close()

    t = threading.Thread(target=_loop, name="scheduler", daemon=True)
    t.start()


@rest_api.get("/api/test-master")
def rest_test_master_get():
    return _rest_handle("TEST_MASTER_GET", {"activeOnly": True})


@rest_api.post("/api/candidates/<candidate_id>/required-tests")
def rest_candidate_required_tests(candidate_id: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "CANDIDATE_REQUIRED_TESTS_SET",
        {
            "candidateId": candidate_id,
            "requirementId": body.get("requirementId") or "",
            "testKeys": body.get("testKeys") or [],
        },
    )


@rest_api.post("/api/candidates/<candidate_id>/tests/<test_key>/submit")
def rest_candidate_test_submit(candidate_id: str, test_key: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "CANDIDATE_TEST_SUBMIT",
        {
            "candidateId": candidate_id,
            "requirementId": body.get("requirementId") or "",
            "testKey": test_key,
            "marks": body.get("marks"),
            "remarks": body.get("remarks") or "",
        },
    )


@rest_api.post("/api/candidates/<candidate_id>/tests/<test_key>/review")
def rest_candidate_test_review(candidate_id: str, test_key: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "CANDIDATE_TEST_REVIEW",
        {
            "candidateId": candidate_id,
            "requirementId": body.get("requirementId") or "",
            "testKey": test_key,
            "decision": body.get("decision") or "",
            "remarks": body.get("remarks") or "",
        },
    )


@rest_api.get("/api/candidates/fail")
def rest_fail_candidates_list():
    stage = str(request.args.get("stageName") or "").strip()
    include_resolved = str(request.args.get("includeResolved") or "").strip()
    return _rest_handle(
        "FAIL_CANDIDATES_LIST",
        {"stageName": stage, "includeResolved": include_resolved in {"1", "true", "TRUE", "yes", "YES"}},
    )


@rest_api.post("/api/candidates/<candidate_id>/training/mark-complete")
def rest_training_mark_complete(candidate_id: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "TRAINING_MARK_COMPLETE",
        {"candidateId": candidate_id, "requirementId": body.get("requirementId") or ""},
    )


@rest_api.post("/api/candidates/<candidate_id>/training/close")
def rest_training_close(candidate_id: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "TRAINING_CLOSE",
        {"candidateId": candidate_id, "requirementId": body.get("requirementId") or ""},
    )


@rest_api.post("/api/candidates/<candidate_id>/probation/complete")
def rest_probation_complete(candidate_id: str):
    body = request.get_json(silent=True) or {}
    return _rest_handle(
        "PROBATION_COMPLETE",
        {"candidateId": candidate_id, "requirementId": body.get("requirementId") or ""},
    )


@rest_api.post("/api/jobs/auto-reschedule-no-show")
def rest_auto_reschedule_no_show():
    body = request.get_json(silent=True) or {}
    return _rest_handle("AUTO_RESCHEDULE_NO_SHOW", {"dryRun": bool(body.get("dryRun")), "limit": body.get("limit")}, allow_internal=True)


@rest_api.get("/api/admin/sla-config")
def rest_sla_config_get():
    return _rest_handle("SLA_CONFIG_GET", {})


@rest_api.post("/api/admin/sla-config")
def rest_sla_config_upsert():
    body = request.get_json(silent=True) or {}
    return _rest_handle("SLA_CONFIG_UPSERT", {"items": body.get("items") or []})


@rest_api.get("/api/metrics/step-metrics")
def rest_step_metrics_query():
    params = {
        "stepName": str(request.args.get("stepName") or "").strip(),
        "requirementId": str(request.args.get("requirementId") or "").strip(),
        "candidateId": str(request.args.get("candidateId") or "").strip(),
        "dateFrom": str(request.args.get("dateFrom") or "").strip(),
        "dateTo": str(request.args.get("dateTo") or "").strip(),
    }
    return _rest_handle("STEP_METRICS_QUERY", params)


def _configure_logging(level: str):
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _seed_roles_and_permissions(db):
    now = iso_utc_now()
    actor = "SYSTEM_INIT"

    # Roles seed
    existing_roles = {r.roleCode.upper() for r in db.query(Role).all()}  # type: ignore[attr-defined]
    needed = ["ADMIN", "EA", "HR", "OWNER", "EMPLOYEE", "ACCOUNTS", "MIS", "DEO"]
    for rc in needed:
        if rc in existing_roles:
            continue
        db.add(
            Role(
                roleCode=rc,
                roleName=rc,
                status="ACTIVE",
                createdAt=now,
                createdBy=actor,
                updatedAt=now,
                updatedBy=actor,
            )
        )

    # Permissions seed (idempotent; only inserts missing keys to avoid overriding custom RBAC).
    existing_perm = {
        (str(p.permType or "").upper().strip(), str(p.permKey or "").upper().strip()): p
        for p in db.query(Permission).all()  # type: ignore[attr-defined]
    }

    ui_rows = [
        ("UI", "PORTAL_ADMIN", "ADMIN", True),
        ("UI", "PORTAL_REQUIREMENTS", "EA,ADMIN", True),
        ("UI", "PORTAL_HR_REVIEW", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_PRECALL", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_PREINTERVIEW", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_INPERSON", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_FINAL", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_FINAL_HOLD", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_JOINING", "HR,ADMIN", True),
        ("UI", "PORTAL_HR_PROBATION", "HR,EA,ADMIN", True),
        ("UI", "PORTAL_OWNER", "OWNER,ADMIN", True),
        ("UI", "PORTAL_EA_TECH", "EA,ADMIN", True),
        ("UI", "PORTAL_REJECTION_LOG", "EA,HR,ADMIN", True),
        ("UI", "PORTAL_EMPLOYEE_PROFILE", "EA,HR,OWNER,ADMIN", True),
        ("UI", "PORTAL_FAIL_CANDIDATES", "HR,ADMIN", True),
        ("UI", "PORTAL_TESTS", "HR,EA,ADMIN,ACCOUNTS,MIS,DEO", True),
        ("UI", "PORTAL_ADMIN_SLA", "ADMIN", True),
        ("UI", "BTN_SHORTLIST_OWNER_SEND", "HR,ADMIN", True),
        ("UI", "BTN_OWNER_APPROVE_WALKIN", "OWNER,ADMIN", True),
        ("UI", "SECTION_EXCEL_MARKS", "ADMIN", True),
    ]

    for perm_type, perm_key, roles_csv, enabled in ui_rows:
        k = (perm_type.upper(), perm_key.upper())
        if k in existing_perm:
            continue
        db.add(
            Permission(
                permType=perm_type,
                permKey=perm_key,
                rolesCsv=roles_csv,
                enabled=bool(enabled),
                updatedAt=now,
                updatedBy=actor,
            )
        )

    # ACTION permissions seed from static mapping (idempotent).
    from auth import STATIC_RBAC_PERMISSIONS

    for action, roles in STATIC_RBAC_PERMISSIONS.items():
        key = action.upper()
        k2 = ("ACTION", key)
        if k2 in existing_perm:
            continue
        db.add(
            Permission(
                permType="ACTION",
                permKey=key,
                rolesCsv=",".join(roles),
                enabled=True,
                updatedAt=now,
                updatedBy=actor,
            )
        )


def _seed_test_master(db):
    now = iso_utc_now()
    actor = "SYSTEM_INIT"

    existing = {str(r.testKey or "").upper().strip() for r in db.query(TestMaster).all()}  # type: ignore[attr-defined]

    defaults = [
        {
            "testKey": "EXCEL",
            "label": "Excel",
            "fillRoles": ["MIS", "DEO", "ADMIN"],
            "reviewRoles": ["HR", "ADMIN"],
            "ordering": 10,
        },
        {
            "testKey": "TALLY",
            "label": "Tally",
            "fillRoles": ["ACCOUNTS", "ADMIN"],
            "reviewRoles": ["HR", "ADMIN"],
            "ordering": 20,
        },
        {
            "testKey": "VOICE",
            "label": "Voice",
            "fillRoles": ["EA", "ADMIN"],
            "reviewRoles": ["HR", "ADMIN"],
            "ordering": 30,
        },
        {
            "testKey": "MEMORY",
            "label": "Memory",
            "fillRoles": ["EA", "ADMIN"],
            "reviewRoles": ["HR", "ADMIN"],
            "ordering": 40,
        },
    ]

    for row in defaults:
        k = str(row.get("testKey") or "").upper().strip()
        if not k or k in existing:
            continue
        db.add(
            TestMaster(
                testKey=k,
                label=str(row.get("label") or k),
                fillRolesJson=json.dumps(row.get("fillRoles") or []),
                reviewRolesJson=json.dumps(row.get("reviewRoles") or []),
                active=True,
                ordering=int(row.get("ordering") or 0),
                createdAt=now,
                createdBy=actor,
                updatedAt=now,
                updatedBy=actor,
            )
        )


def _seed_sla_config(db):
    now = iso_utc_now()
    actor = "SYSTEM_INIT"

    existing = {str(r.stepName or "").upper().strip() for r in db.query(SLAConfig).all()}  # type: ignore[attr-defined]
    steps = [
        "HR_REVIEW",
        "JOB_POSTING",
        "ADD_CANDIDATE",
        "PRECALL",
        "PRE_INTERVIEW",
        "ONLINE_TEST",
        "IN_PERSON",
        "TECHNICAL",
        "FINAL_INTERVIEW",
        "JOINING",
        "DOCS",
        "TRAINING",
        "PROBATION",
    ]

    for s in steps:
        if s in existing:
            continue
        db.add(SLAConfig(stepName=s, plannedMinutes=0, enabled=True, updatedAt=now, updatedBy=actor))


def create_app() -> Flask:
    load_dotenv()
    cfg = Config()
    cfg.validate()
    _configure_logging(cfg.LOG_LEVEL)

    engine = init_engine(cfg.DATABASE_URL)
    if SessionLocal is None:
        raise RuntimeError("DB not initialized")

    # Optional sharding scaffold (off by default). Configure DB_URL_0..DB_URL_N to enable.
    try:
        from db import init_shard_engines

        if isinstance(getattr(cfg, "DB_URLS", None), list) and len(cfg.DB_URLS) > 1:
            init_shard_engines(cfg.DB_URLS)
    except Exception:
        pass

    from models import Base  # imported after engine init

    Base.metadata.create_all(bind=engine)

    # Lightweight schema evolution (adds new columns/indexes + backfills PII hashes/masks).
    from schema import ensure_schema

    ensure_schema(engine)

    app = Flask(__name__)
    app.config["CFG"] = cfg

    CORS(app, origins=cfg.ALLOWED_ORIGINS, supports_credentials=False)
    app.register_blueprint(rest_api)

    limiter = SimpleRateLimiter()

    # Seed roles/permissions at startup (idempotent).
    db0 = SessionLocal()
    try:
        _seed_roles_and_permissions(db0)
        _seed_test_master(db0)
        _seed_sla_config(db0)
        db0.commit()
    finally:
        db0.close()

    @app.before_request
    def _before():
        g.request_id = os.urandom(8).hex()
        g.start_ts = now_monotonic()

    @app.after_request
    def _after(resp):
        try:
            resp.headers["X-Request-ID"] = str(getattr(g, "request_id", "") or "")
        except Exception:
            pass
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/health")
    def health():
        return ok({"status": "ok"})[0]

    @app.get("/")
    def index():
        return ok(
            {
                "status": "ok",
                "message": "HRMS backend is running. Use /health for a quick check and POST /api for actions.",
                "endpoints": {"health": "/health", "api": "/api"},
                "note": "In a browser, open http://127.0.0.1:5000/health (do not type 'GET /health' in the URL).",
            }
        )[0]

    @app.get("/files/<file_id>")
    def files_get(file_id: str):
        cfg2: Config = app.config["CFG"]
        fid = str(file_id or "").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{32}", fid):
            return err("BAD_REQUEST", "Invalid file id", http_status=400)[0], 400

        token_q = str(request.args.get("token") or "").strip()
        token_h = str(request.headers.get("Authorization") or "").strip()
        token = token_q
        if token_h.lower().startswith("bearer "):
            token = token_h[7:].strip()

        if not token:
            return err("AUTH_INVALID", "Missing token", http_status=401)[0], 401

        db = SessionLocal()
        try:
            auth_ctx = validate_session_token(db, token)
            if not auth_ctx.valid:
                return err("AUTH_INVALID", "Invalid or expired session", http_status=401)[0], 401

            role = role_or_public(auth_ctx)
            if role == "PUBLIC":
                return err("AUTH_INVALID", "Login required", http_status=401)[0], 401

            # EMPLOYEE role can only access its own candidate/employee files.
            if role == "EMPLOYEE":
                try:
                    from sqlalchemy import select

                    from models import Candidate, Employee

                    emp = db.execute(select(Employee).where(Employee.employeeId == str(auth_ctx.userId or ""))).scalar_one_or_none()
                    if not emp:
                        return err("FORBIDDEN", "Employee not found", http_status=403)[0], 403

                    allowed = set()
                    if str(emp.cvFileId or "").strip():
                        allowed.add(str(emp.cvFileId).strip())

                    cand_id = str(emp.candidateId or "").strip()
                    if cand_id:
                        cand = db.execute(select(Candidate).where(Candidate.candidateId == cand_id)).scalar_one_or_none()
                        if cand and str(cand.cvFileId or "").strip():
                            allowed.add(str(cand.cvFileId).strip())
                        try:
                            docs = json.loads(str(getattr(cand, "docsJson", "") or "[]")) if cand else []
                            if isinstance(docs, list):
                                for d in docs:
                                    if isinstance(d, dict) and str(d.get("fileId") or "").strip():
                                        allowed.add(str(d.get("fileId")).strip())
                        except Exception:
                            pass

                    if fid not in allowed:
                        return err("FORBIDDEN", "File not accessible", http_status=403)[0], 403
                except Exception:
                    return err("FORBIDDEN", "File not accessible", http_status=403)[0], 403

            pattern = os.path.join(cfg2.UPLOAD_DIR, f"{fid}_*")
            matches = sorted(glob.glob(pattern))
            if not matches:
                return err("NOT_FOUND", "File not found", http_status=404)[0], 404

            path = matches[0]
            name = os.path.basename(path)
            download_name = name[len(fid) + 1 :] if name.startswith(fid + "_") else name
            mime, _enc = mimetypes.guess_type(download_name)
            mime = mime or "application/octet-stream"

            resp = send_file(path, mimetype=mime, as_attachment=False, download_name=download_name)
            resp.headers["X-Content-Type-Options"] = "nosniff"
            return resp
        finally:
            try:
                db.close()
            except Exception:
                pass

    @app.errorhandler(404)
    def not_found(_e):
        path = request.path
        return (
            err(
                "NOT_FOUND",
                f"Unknown endpoint: {path}. Use GET /health in browser, and POST /api for actions (don’t type 'GET'/'POST' in the URL).",
                http_status=404,
            )
        )

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return err("BAD_REQUEST", "Method not allowed. Use POST /api for actions.", http_status=405)

    @app.post("/api")
    def api_route():
        cfg2: Config = app.config["CFG"]
        raw = request.get_data(as_text=True)
        db = None
        auth_ctx = None
        action_u = ""
        token = None
        data: Any = {}

        try:
            body = parse_json_body(raw)
            action_u = str(body.get("action") or "").upper().strip()
            token = body.get("token")
            data = body.get("data") or {}

            if not action_u:
                raise ApiError("BAD_REQUEST", "Missing action")

            ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
            login_actions = {"LOGIN_EXCHANGE", "EMPLOYEE_LOGIN"}
            if action_u in login_actions:
                limiter.check(f"{ip}:LOGIN", cfg2.RATE_LIMIT_LOGIN)
            else:
                # Use a generous global limit + a per-action limit to avoid blocking normal SPA usage.
                limiter.check(f"{ip}:GLOBAL", cfg2.RATE_LIMIT_GLOBAL)
                limiter.check(f"{ip}:API:{action_u}", cfg2.RATE_LIMIT_DEFAULT)

            db = SessionLocal()

            if action_u != "LOGIN_EXCHANGE" and not is_public_action(action_u):
                auth_ctx = validate_session_token(db, token)
                if not auth_ctx.valid:
                    raise ApiError("AUTH_INVALID", "Invalid or expired session")
            else:
                if token:
                    maybe = validate_session_token(db, token)
                    auth_ctx = maybe if maybe.valid else None

            role = role_or_public(auth_ctx)
            assert_permission(db, role, action_u)

            out = dispatch(action_u, data, auth_ctx, db, cfg2)

            # Audit API_CALL
            try:
                db.add(
                    AuditLog(
                        logId=f"LOG-{os.urandom(16).hex()}",
                        entityType="API",
                        entityId=str(auth_ctx.userId or auth_ctx.email or "") if auth_ctx else "PUBLIC",
                        action=action_u,
                        fromState="",
                        toState="",
                        stageTag="API_CALL",
                        remark="",
                        actorUserId=str(auth_ctx.userId) if auth_ctx else "PUBLIC",
                        actorRole=str(auth_ctx.role) if auth_ctx else "PUBLIC",
                        at=iso_utc_now(),
                        metaJson=json.dumps({"data": redact_for_audit(data)}),
                    )
                )
            except Exception:
                pass

            db.commit()

            latency_ms = int((now_monotonic() - g.start_ts) * 1000)
            logging.getLogger("api").info(
                "request_id=%s action=%s user=%s role=%s latency_ms=%s",
                g.request_id,
                action_u,
                (auth_ctx.userId if auth_ctx else "PUBLIC"),
                (auth_ctx.role if auth_ctx else "PUBLIC"),
                latency_ms,
            )

            return ok(out)[0]
        except ApiError as e:
            if db is not None:
                db.rollback()
            _write_error_audit(cfg2, action_u, auth_ctx, data, e)
            return err(e.code, e.message, http_status=e.http_status)[0], e.http_status
        except Exception:
            if db is not None:
                db.rollback()
            api_err = ApiError("INTERNAL", "Unexpected error")
            _write_error_audit(cfg2, action_u, auth_ctx, data, api_err)
            logging.getLogger("api").exception("request_id=%s action=%s", g.request_id, action_u)
            return err(api_err.code, api_err.message)[0]
        finally:
            if db is not None:
                db.close()

    _maybe_start_internal_scheduler(cfg)
    return app


def _write_error_audit(cfg: Config, action: str, auth_ctx, data: Any, err_obj: ApiError):
    if SessionLocal is None:
        return
    try:
        db2 = SessionLocal()
        db2.add(
            AuditLog(
                logId=f"LOG-{os.urandom(16).hex()}",
                entityType="API",
                entityId=str(auth_ctx.userId or auth_ctx.email or "") if auth_ctx else "PUBLIC",
                action=str(action or "").upper() or "UNKNOWN",
                fromState="",
                toState="",
                stageTag="API_ERROR",
                remark=f"{err_obj.code}: {err_obj.message}",
                actorUserId=str(auth_ctx.userId) if auth_ctx else "PUBLIC",
                actorRole=str(auth_ctx.role) if auth_ctx else "PUBLIC",
                at=iso_utc_now(),
                metaJson=json.dumps(
                    {
                        "data": redact_for_audit(data or {}),
                        "error": {"code": err_obj.code, "message": err_obj.message},
                    }
                ),
            )
        )
        db2.commit()
    except Exception:
        pass
    finally:
        try:
            db2.close()
        except Exception:
            pass


if __name__ == "__main__":
    app = create_app()
    cfg = app.config["CFG"]

    os.makedirs(cfg.UPLOAD_DIR, exist_ok=True)
    app.run(host=cfg.HOST, port=cfg.PORT)
