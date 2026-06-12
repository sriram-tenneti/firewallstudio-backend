"""FastAPI application entry point for Network Firewall Studio Backend.

Architecture:
  Browser → Express BFF (auth, aggregation) → THIS FastAPI (business logic)

Data Store:
  DATA_STORE=json   → reads/writes JSON files in data/ (default for dev)
  DATA_STORE=mongodb → uses Motor async MongoDB driver (for production)
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.store import get_store, JsonFileStore
from app.middleware.audit_middleware import AuditMiddleware

from app.routes.rules import router as rules_router
from app.routes.requests import router as requests_router
from app.routes.groups import router as groups_router
from app.routes.reference import router as reference_router
from app.routes.policy import router as policy_router
from app.routes.reviews import router as reviews_router
from app.routes.lifecycle import router as lifecycle_router
from app.routes.migrations import router as migrations_router
from app.routes.shared_services import router as shared_services_router
from app.routes.audit import router as audit_router
from app.routes.seed import router as seed_router
from app.routes.export import router as export_router
from app.routes.admin import router as admin_router
from app.routes.validation import router as validation_router
from app.routes.compile import router as compile_router
from app.routes.birthright import router as birthright_router
from app.routes.itsm import router as itsm_router
from app.routes.migration_apply import router as migration_apply_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup: initialize data store. Shutdown: clean up connections."""
    store = get_store()

    if isinstance(store, JsonFileStore):
        counts = await store.load_from_files()
        total = sum(counts.values())
        logger.info(f"JSON store loaded: {total} documents across {len(counts)} collections")
    else:
        # MongoDB mode — ensure indexes
        from app.db.connection import get_db, close_connection
        from app.db.indexes import ensure_indexes
        db = get_db()
        await ensure_indexes(db)

    logger.info(f"Data store mode: {settings.data_store}")
    yield

    # Cleanup
    if settings.data_store == "mongodb":
        from app.db.connection import close_connection
        await close_connection()


app = FastAPI(
    title="Network Firewall Studio — Backend API",
    version="1.0.0",
    description=f"Data store: {settings.data_store}",
    lifespan=lifespan,
)

# CORS — in production the BFF is the only origin; dev allows localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Audit middleware — adds correlation IDs
app.add_middleware(AuditMiddleware)

# Route order matters: specific prefixes before catch-all patterns
app.include_router(admin_router)          # /api/admin/*
app.include_router(validation_router)     # /api/validation/*
app.include_router(compile_router)        # /api/compile/*
app.include_router(birthright_router)     # /api/birthright-rules, /api/validate-birthright-cross-dc
app.include_router(itsm_router)           # /api/itsm/*
app.include_router(migration_apply_router) # /api/migration/apply*
app.include_router(shared_services_router)
app.include_router(groups_router)
app.include_router(rules_router)
app.include_router(requests_router)
app.include_router(reference_router)
app.include_router(policy_router)
app.include_router(reviews_router)
app.include_router(lifecycle_router)
app.include_router(migrations_router)
app.include_router(audit_router)
app.include_router(seed_router)
app.include_router(export_router)


@app.get("/healthz")
async def healthz():
    store = get_store()
    return {
        "status": "ok",
        "data_store": settings.data_store,
        "store_type": type(store).__name__,
    }
