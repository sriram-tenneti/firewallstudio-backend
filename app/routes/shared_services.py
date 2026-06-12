"""Shared services specific endpoints — presences, fan-out, etc."""

from fastapi import APIRouter, Depends, Query
from typing import Optional

from app.db.collections import col, SHARED_SERVICE_PRESENCES
from app.middleware.auth import CurrentUser, get_current_user
from app.models.base import utc_now
from app.services.audit import record_audit

router = APIRouter(prefix="/api/shared-services", tags=["Shared Services"])


@router.get("/presences")
async def list_presences(
    service_id: Optional[str] = Query(None),
    dc_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
):
    query: dict = {}
    if service_id:
        query["service_id"] = service_id
    if dc_id:
        query["dc_id"] = dc_id
    if environment:
        query["environment"] = environment

    cursor = col(SHARED_SERVICE_PRESENCES).find(query).limit(500)
    results = await cursor.to_list(length=500)
    for r in results:
        r.pop("_id", None)
    return results


@router.post("/presences")
async def create_presence(data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    data["created_at"] = now
    data["created_by"] = user.user_id
    data["updated_at"] = now
    data["updated_by"] = user.user_id
    result = await col(SHARED_SERVICE_PRESENCES).insert_one(data)
    await record_audit(
        "shared_service_presences", str(result.inserted_id), "create",
        user.user_id, user.user_email, user.user_team,
        after_snapshot=_s(data),
    )
    data.pop("_id", None)
    return data


def _s(doc: dict | None) -> dict | None:
    if doc is None:
        return None
    d = dict(doc)
    d.pop("_id", None)
    return d
