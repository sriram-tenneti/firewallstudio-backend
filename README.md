# Firewall Studio — Backend

FastAPI backend for Network Firewall Studio with dual data store (JSON files or MongoDB), encrypted collections, full audit trails, and request status state machine.

## Architecture

```
Express BFF (frontend repo) → THIS FastAPI → JSON files (dev) / MongoDB (prod)
```

## Data Store Switch

The backend supports two storage modes, toggled by `DATA_STORE` env var:

| Mode | When | Config |
|------|------|--------|
| `json` (default) | Development — no MongoDB needed | Reads/writes JSON files in `data/` |
| `mongodb` | Production | Uses Motor async MongoDB driver |

```bash
# Development with JSON files (default)
DATA_STORE=json uvicorn app.main:app --port 8000

# Production with MongoDB
DATA_STORE=mongodb MONGODB_URI=mongodb://... uvicorn app.main:app --port 8000
```

**Runtime switching** (no restart needed):
```bash
curl -X POST http://localhost:8000/api/admin/store/switch -d "mode=mongodb"
```

**Upload JSON to MongoDB** (migrate dev data → prod):
```bash
curl -X POST http://localhost:8000/api/admin/store/upload-to-mongo
```

## Quick Start

```bash
# Prerequisites: Python 3.11+

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start with JSON files (no MongoDB needed!)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Check status
curl http://localhost:8000/healthz
curl http://localhost:8000/api/admin/store/status
```

## API Docs

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_STORE` | `json` | `json` or `mongodb` |
| `JSON_DATA_DIR` | `data` | Path to JSON files directory |
| `MONGODB_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGODB_DATABASE` | `firewall_studio` | Database name |
| `ENCRYPTION_ENABLED` | `false` | Enable CSFLE field encryption |
| `KMS_PROVIDER` | `local` | KMS provider: `local`, `aws`, `azure`, `gcp` |

## 10 Consolidated Collections

| Collection | Discriminator | Purpose |
|---|---|---|
| `applications` | — | App profiles with nested presences |
| `groups` | `group_type: firewall\|ingress` | All groups; ingress carry VIP/endpoint refs |
| `requests` | `request_type: rule\|group_change` | All request types |
| `compiled_rules` | — | Physical/compiled rules for all requests |
| `reference_data` | `ref_type: neighbourhood\|security_zone\|...` | NH, SZ, DC, policy, ports, naming |
| `request_status_history` | — | Append-only status transitions |
| `audit_trail` | — | Every data mutation with before/after |
| `reviews` | — | Review/approval records |
| `migrations` | — | Migration data + mappings |
| `shared_services` | `service_type: shared_service\|itsm_connector` | Shared services + ITSM config |

## Project Structure

```
app/
├── main.py                # FastAPI entry point
├── config.py              # Settings (DATA_STORE switch)
├── db/
│   ├── store.py           # DataStore abstraction (JSON + MongoDB)
│   ├── connection.py      # Motor MongoDB client
│   ├── collections.py     # 10 consolidated collection names
│   ├── encryption.py      # CSFLE setup
│   └── indexes.py         # Index definitions
├── models/                # Pydantic models
├── routes/
│   ├── admin.py           # Store management, upload, switch
│   ├── rules.py           # Rule CRUD
│   ├── requests.py        # Request status history
│   ├── groups.py          # Group + ingress CRUD
│   ├── reference.py       # Reference data CRUD
│   ├── export.py          # XLSX export with Destination Host
│   ├── ... (policy, reviews, lifecycle, migrations, audit, seed)
├── services/
│   ├── audit.py           # Audit trail recording
│   ├── lifecycle.py       # State machine + transitions
│   └── export.py          # XLSX builder with VIP/endpoint
└── middleware/
    ├── auth.py            # User identity from BFF headers
    └── audit_middleware.py

data/                      # JSON seed files (10 files, one per collection)
├── applications.json
├── groups.json
├── requests.json
├── compiled_rules.json
├── reference_data.json
├── request_status_history.json
├── audit_trail.json
├── reviews.json
├── migrations.json
└── shared_services.json
```

## Admin Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/store/status` | GET | Current mode + collection counts |
| `/api/admin/store/switch` | POST | Switch json ↔ mongodb at runtime |
| `/api/admin/store/reload` | POST | Reload JSON files from disk |
| `/api/admin/store/upload-to-mongo` | POST | Load all JSON → MongoDB |
| `/api/admin/store/upload-json/{collection}` | POST | Upload JSON file for one collection |
| `/api/admin/store/export-json/{collection}` | GET | Export collection as JSON |
| `/api/admin/store/collections` | GET | List collections + file mappings |
