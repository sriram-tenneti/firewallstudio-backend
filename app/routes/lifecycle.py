"""Lifecycle management endpoints — events, timeline, transitions."""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional

from app.db.collections import col, LIFECYCLE_EVENTS
from app.middleware.auth import CurrentUser, get_current_user
from app.models.base import utc_now

router = APIRouter(prefix="/api/lifecycle", tags=["Lifecycle Management"])


@router.get("/events")
async def list_lifecycle_events(
    rule_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    module: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
):
    """Query lifecycle events."""
    query: dict = {}
    if rule_id:
        query["rule_id"] = rule_id
    if event_type:
        query["event_type"] = event_type
    if module:
        query["module"] = module

    cursor = (
        col(LIFECYCLE_EVENTS)
        .find(query)
        .sort("timestamp", -1)
        .skip(offset)
        .limit(limit)
    )
    results = await cursor.to_list(length=limit)
    for r in results:
        r.pop("_id", None)
    return results


@router.get("/events/{rule_id}/timeline")
async def get_rule_timeline(rule_id: str):
    """Full timeline for a rule, oldest-first."""
    cursor = (
        col(LIFECYCLE_EVENTS)
        .find({"rule_id": rule_id})
        .sort("timestamp", 1)
    )
    results = await cursor.to_list(length=500)
    for r in results:
        r.pop("_id", None)
    return results


@router.post("/events")
async def record_event(
    data: dict,
    user: CurrentUser = Depends(get_current_user),
):
    """Record a lifecycle event."""
    import uuid
    data["_id"] = f"evt-{uuid.uuid4().hex[:12]}"
    data["timestamp"] = data.get("timestamp", utc_now())
    data["actor"] = data.get("actor", user.user_id)
    await col(LIFECYCLE_EVENTS).insert_one(data)
    data.pop("_id", None)
    return data
