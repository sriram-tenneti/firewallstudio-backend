"""Migration workflow endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional

from app.db.collections import col, MIGRATIONS, MIGRATION_MAPPINGS, MIGRATION_RULE_LIFECYCLE
from app.middleware.auth import CurrentUser, get_current_user
from app.models.base import utc_now
from app.services.audit import record_audit

router = APIRouter(prefix="/api/migrations", tags=["Migration Studio"])


@router.get("")
async def list_migrations(
    application: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    query: dict = {}
    if application:
        query["application"] = application
    if status:
        query["status"] = status

    cursor = col(MIGRATIONS).find(query).sort("created_at", -1)
    results = await cursor.to_list(length=200)
    for r in results:
        r.pop("_id", None)
    return results


@router.get("/{migration_id}")
async def get_migration(migration_id: str):
    doc = await col(MIGRATIONS).find_one({"id": migration_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Migration not found")
    doc.pop("_id", None)
    return doc


@router.post("")
async def create_migration(data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    mig_id = f"MIG-{uuid.uuid4().hex[:8]}"
    data["id"] = mig_id
    data["status"] = "Draft"
    data["created_at"] = now
    await col(MIGRATIONS).insert_one(data)
    await record_audit("migrations", mig_id, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


@router.get("/{migration_id}/mappings")
async def list_migration_mappings(migration_id: str):
    cursor = col(MIGRATION_MAPPINGS).find({"migration_id": migration_id})
    results = await cursor.to_list(length=500)
    for r in results:
        r.pop("_id", None)
    return results


@router.get("/{migration_id}/rules")
async def list_migration_rules(migration_id: str):
    cursor = col(MIGRATION_RULE_LIFECYCLE).find({"migration_id": migration_id})
    results = await cursor.to_list(length=500)
    for r in results:
        r.pop("_id", None)
    return results


def _s(doc: dict | None) -> dict | None:
    if doc is None:
        return None
    d = dict(doc)
    d.pop("_id", None)
    return d
