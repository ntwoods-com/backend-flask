# HRMS Backend (Flask + Supabase Postgres)

Flask backend for the HRMS React frontend (`HRMS-NTWOODS`) using Supabase Postgres (via SQLAlchemy).

## Quickstart (local)

```bash
cd backend-flask
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
copy .env.example .env
python legacy_app.py
```

Backend runs on `http://127.0.0.1:5002` (see `PORT`).

## API

- `GET /health`
- `POST /api` (single action router; matches the frontend client)
  - Body: `{ "action": "ACTION_NAME", "token": "<sessionToken|null>", "data": { ... } }`
- `GET /files/<fileId>?token=<sessionToken>`

## Supabase setup

1) Create a Supabase project.
2) Copy the Postgres connection string (prefer the “Connection pooling” URL when available).
3) Set `DATABASE_URL` in `.env` (include `?sslmode=require`).

Important: tune `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, and Gunicorn `WEB_CONCURRENCY` to stay within Supabase connection limits.

## Production env (minimum)

- `APP_ENV=production`
- `DATABASE_URL=...`
- `PEPPER=...` (long random string)
- `GOOGLE_CLIENT_ID=...`
- `ALLOWED_ORIGINS=https://your-frontend-domain`

## Deploy (Gunicorn)

This repo includes:
- `Procfile` (process entry)
- `gunicorn.conf.py` (workers/threads via env vars)
- `wsgi.py` (Gunicorn import target)

Start command:

```bash
gunicorn wsgi:app -c gunicorn.conf.py
```
