# Firewall Studio — Backend

FastAPI backend for Network Firewall Studio with MongoDB, encrypted collections, full audit trails, and request status state machine.

## Architecture

```
Express BFF (frontend repo) → THIS FastAPI → MongoDB
```

The BFF authenticates users and forwards identity in `X-User-Id`, `X-User-Email`, `X-User-Team` headers.

## Quick Start

```bash
# Prerequisites: Python 3.11+, MongoDB running on localhost:27017

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start the server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Seed reference data (one-time)
curl -X POST http://localhost:8000/api/seed/load
```

## API Docs

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Configuration

Environment variables (or `.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGODB_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGODB_DATABASE` | `firewall_studio` | Database name |
| `ENCRYPTION_ENABLED` | `false` | Enable CSFLE field encryption |
| `KMS_PROVIDER` | `local` | KMS provider: `local`, `aws`, `azure`, `gcp` |
| `LOCAL_MASTER_KEY` | *(auto-generated)* | Base64 master key (dev only) |

## Key Collections

| Collection | Primary Key | Purpose |
|---|---|---|
| `applications` | `app_distributed_id` | Application profiles |
| `firewall_groups` | group name | Egress/ingress groups |
| `ingress_groups` | group name | Enhanced ingress with VIP/endpoint refs |
| `rule_requests` | `request_id` | Logical rule requests |
| `physical_rules` | `rule_id` | Per-DC fan-out rules |
| `request_status_history` | auto | State transitions (keyed by `app_distributed_id`) |
| `audit_trail` | auto | Every data mutation captured |

## Project Structure

```
app/
├── main.py              # FastAPI entry point
├── config.py            # Settings from env
├── db/
│   ├── connection.py    # Motor MongoDB client
│   ├── collections.py   # Collection name constants
│   ├── encryption.py    # CSFLE setup
│   └── indexes.py       # Index definitions
├── models/
│   ├── base.py          # AuditMixin (created_at/by, updated_at/by)
│   ├── applications.py  # App, SharedService, Presence models
│   ├── groups.py        # FirewallGroup, IngressGroup (VIP/endpoint)
│   ├── rules.py         # RuleRequest, PhysicalRule, FirewallRule
│   ├── requests.py      # State machine definitions
│   ├── audit.py         # AuditTrailEntry
│   └── reference.py     # NH, SZ, DC, Policy, OrgConfig, etc.
├── routes/
│   ├── rules.py         # Rule request CRUD + transitions
│   ├── requests.py      # Request status history queries
│   ├── groups.py        # Group + ingress group CRUD
│   ├── reference.py     # Reference data CRUD
│   ├── policy.py        # Policy validation
│   ├── reviews.py       # Review/approval queue
│   ├── lifecycle.py     # Lifecycle events + timeline
│   ├── migrations.py    # Migration workflows
│   ├── shared_services.py
│   ├── audit.py         # Audit trail queries
│   └── seed.py          # Seed data loader
├── services/
│   ├── audit.py         # Audit trail recording
│   ├── lifecycle.py     # State machine + request history
│   └── naming_standards.py
└── middleware/
    ├── auth.py          # User identity from BFF headers
    └── audit_middleware.py
```
