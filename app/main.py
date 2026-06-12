"""FastAPI application entry point for Network Firewall Studio Backend.

Architecture:
  Browser → Express BFF (auth, aggregation) → THIS FastAPI (business logic, MongoDB)
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db.connection import get_db, close_connection
from app.db.indexes import ensure_indexes
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


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup: ensure indexes. Shutdown: close MongoDB connection."""
    db = get_db()
    await ensure_indexes(db)
    yield
    await close_connection()


app = FastAPI(
    title="Network Firewall Studio — Backend API",
    version="1.0.0",
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
    return {"status": "ok"}
