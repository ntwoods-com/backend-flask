# HRMS Backend (Flask + MongoDB Atlas + JWT + Reports)

Production-ready Flask API for a GitHub Pages React frontend + MongoDB Atlas backend, with reporting endpoints and Excel export for Power BI/ETL.

## Project structure

- `app/__init__.py` (create_app factory)
- `app/config.py` (dev/prod/test config, env-driven)
- `app/routes/` (Blueprints: `auth`, `core`, `reports`)
- `app/db.py` (global MongoClient + indexes)
- `app/utils/` (validators, auth, datetime, rate limiter)
- `app/middlewares/` (request_id, logging, rate limit, error handler, security headers)
- `wsgi.py` (Gunicorn entrypoint)

## Setup (local)

```bash
cd backend-flask
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
copy .env.example .env
python -c "from app import create_app; create_app().run(port=5000, debug=True)"
```

## Environment

All env vars are documented in `.env.example`.

Required in production:
- `ENV=production`
- `MONGODB_URI` (MongoDB Atlas connection string)
- `DB_NAME`
- `JWT_SECRET`
- `CORS_ORIGINS` (comma-separated; for GitHub Pages use `https://<username>.github.io`)

## Endpoints

Open:
- `GET /health` → `{status,time,version,db}` (includes Mongo ping)
- `GET /version`

Auth (JWT):
- `POST /api/v1/auth/bootstrap` (one-time first admin; requires `BOOTSTRAP_TOKEN` + `X-Bootstrap-Token` header)
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me`
- `POST /api/v1/auth/users` (ADMIN/OWNER)

Reports (JWT + role protected):
- `GET /api/v1/reports/summary?from=YYYY-MM-DD&to=YYYY-MM-DD`
- `GET /api/v1/reports/funnel?from=YYYY-MM-DD&to=YYYY-MM-DD&department=...`
- `GET /api/v1/reports/export.xlsx?from=YYYY-MM-DD&to=YYYY-MM-DD&type=funnel|summary&department=...`

## Example curl (Postman-ready payloads)

Bootstrap first user (only when `users` collection is empty):
```bash
curl -X POST "$BASE_URL/api/v1/auth/bootstrap" \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
  -d '{"email":"admin@example.com","password":"password123","role":"ADMIN"}'
```

Login:
```bash
curl -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"password123"}'
```

Summary report:
```bash
curl "$BASE_URL/api/v1/reports/summary?from=2026-01-01&to=2026-01-31" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Excel export:
```bash
curl -L "$BASE_URL/api/v1/reports/export.xlsx?from=2026-01-01&to=2026-01-31&type=summary" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -o report.xlsx
```

## Render deploy steps

1) Push this backend to GitHub.
2) On Render: **New → Web Service** → connect repo.
3) Set:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`
4) Add env vars from `.env.example` (never commit secrets).

## MongoDB Atlas setup (notes)

- Create a database user (least privilege recommended for production).
- Network access:
  - Easiest: allow `0.0.0.0/0` (not ideal, but common on Render free tier because outbound IP may change).
  - Better: use a paid plan / static egress IP allowlist.
- Ensure your Atlas user/password is URL-encoded in `MONGODB_URI`.

## Keep-warm (reduce cold starts)

Free tier cold start cannot be fully eliminated; pinging just reduces the frequency.

This repo includes `.github/workflows/keepalive.yml`. To enable:
- Add GitHub Actions secret `RENDER_HEALTH_URL` with your Render URL, e.g. `https://<service>.onrender.com/health`

Alternative: use UptimeRobot and monitor `/health`.

## Tests

```bash
cd backend-flask
pytest
```

## Formatting / linting

```bash
black .
ruff check .
```
