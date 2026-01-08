# HRMS Flask Backend (GAS Migration)

This folder contains a Flask + SQLAlchemy backend that matches the existing Google Apps Script `/doPost` contract:

- `POST /api`
- Request JSON: `{ "action": "...", "token": "...", "data": { ... } }`
- Success: `{ "ok": true, "data": ... }`
- Error: `{ "ok": false, "error": { "code": "...", "message": "..." } }`

## Setup (local)

```bash
cd backend-flask
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python app.py
```

## Environment

See `.env.example` for all supported variables.

### Required security env vars

- `PEPPER`: server-side secret used for deterministic PII hashing (HMAC-SHA256). Set a long random value in production.

### Optional performance env vars

- `CACHE_TTL_SECONDS` (default `30`)
- `CACHE_MAX_ITEMS` (default `10000`)

### Sharding scaffold (off by default)

If you want to prepare for sharding, set `DB_URL_0`, `DB_URL_1`, ... (routing helpers exist but core app still uses the primary DB unless you wire sharded sessions in your actions).

## Drive uploads via Google Apps Script (optional)

By default, uploads are stored locally in `UPLOAD_DIR` and opened via `GET /files/<fileId>?token=...`.

If you want CVs/screenshots/docs to be uploaded to Google Drive using your existing Google Apps Script WebApp:

- Set `FILE_STORAGE_MODE=gas`
- Set `GAS_UPLOAD_URL` to your WebApp deployment URL
- Your GAS should accept `fileBase64`, `fileName`, `mimeType` (and optionally `folderId`, `apiKey`) and return JSON containing `fileId` (Drive file id)

## Data migration (optional)

If you export Google Sheets tabs as CSVs (one file per tab), you can import them:

```bash
cd backend-flask
python services/sheets_migration.py --csv-dir ./csv
```

## Endpoints

- `GET /health` (open `http://127.0.0.1:5000/health` in browser)
- `POST /api` (use Postman/curl; don’t type `GET /api` in the browser URL)
- `GET /files/<fileId>?token=ST-...` (opens uploaded CVs/screenshots/docs stored in `UPLOAD_DIR`)

## Quick API test (PowerShell)

```powershell
$body = @{
  action = "GET_ME"
  token  = "ST-..."
  data   = @{}
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/api" -ContentType "application/json" -Body $body
```

## Tests

```bash
cd backend-flask
pytest
```

## Rate limiting

Rate limits are per-IP and configurable via env vars:
- `RATE_LIMIT_DEFAULT` (per-action; default `300 per minute`)
- `RATE_LIMIT_GLOBAL` (overall; default `2000 per minute`)
- `RATE_LIMIT_LOGIN` (login endpoints; default `30 per minute`)
