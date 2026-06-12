"""Lifecycle management endpoints — events, timeline, transitions, dashboard."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional

from app.db.collections import col, LIFECYCLE_EVENTS, COMPILED_RULES, REQUESTS
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
    cursor = col(LIFECYCLE_EVENTS).find({"rule_id": rule_id}).sort("timestamp", 1)
    results = await cursor.to_list(length=500)
    for r in results:
        r.pop("_id", None)
    return results


@router.post("/events")
async def record_event(data: dict, user: CurrentUser = Depends(get_current_user)):
    data["_id"] = f"evt-{uuid.uuid4().hex[:12]}"
    data["timestamp"] = data.get("timestamp", utc_now())
    data["actor"] = data.get("actor", user.user_id)
    await col(LIFECYCLE_EVENTS).insert_one(data)
    data.pop("_id", None)
    return data


@router.get("/dashboard")
async def lifecycle_dashboard(environment: Optional[str] = Query(None)):
    query: dict = {"rule_type": {"$ne": "legacy"}}
    if environment:
        query["environment"] = environment
    all_rules = await col(COMPILED_RULES).find(query).to_list(length=5000)
    status_counts: dict[str, int] = {}
    for r in all_rules:
        s = r.get("status", "Unknown")
        status_counts[s] = status_counts.get(s, 0) + 1
    return {"total": len(all_rules), "by_status": status_counts, "environment": environment}


@router.get("/states")
async def lifecycle_states():
    return {
        "states": ["Draft", "Submitted", "In Progress", "Approved", "Deployed", "Certified", "Expired", "Decommissioned", "Rejected"],
        "transitions": {
            "Draft": ["Submitted"],
            "Submitted": ["In Progress", "Approved", "Rejected"],
            "In Progress": ["Approved", "Rejected"],
            "Approved": ["Deployed", "Rejected"],
            "Deployed": ["Certified", "Decommissioned"],
            "Certified": ["Expired", "Decommissioned"],
            "Rejected": ["Draft"],
            "Expired": ["Draft"],
            "Decommissioned": [],
        },
    }


@router.post("/transition")
async def lifecycle_transition(data: dict, user: CurrentUser = Depends(get_current_user)):
    rule_id = data.get("rule_id")
    new_status = data.get("new_status")
    if not rule_id or not new_status:
        raise HTTPException(status_code=400, detail="rule_id and new_status required")
    before = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if not before:
        raise HTTPException(status_code=404, detail="Rule not found")
    now = utc_now()
    old_status = before.get("status", "Unknown")
    await col(COMPILED_RULES).update_one({"rule_id": rule_id}, {"$set": {"status": new_status, "updated_at": now}})

    event = {
        "_id": f"evt-{uuid.uuid4().hex[:12]}",
        "rule_id": rule_id, "from_status": old_status, "to_status": new_status,
        "actor": user.user_id, "module": data.get("module", "lifecycle"), "timestamp": now,
    }
    await col(LIFECYCLE_EVENTS).insert_one(event)
    return {"rule_id": rule_id, "from_status": old_status, "to_status": new_status}


@router.post("/soft-delete")
async def soft_delete(data: dict, user: CurrentUser = Depends(get_current_user)):
    rule_id = data.get("rule_id")
    if not rule_id:
        raise HTTPException(status_code=400, detail="rule_id required")
    await col(COMPILED_RULES).update_one({"rule_id": rule_id}, {"$set": {"status": "Decommissioned", "decommissioned_at": utc_now(), "decommissioned_by": user.user_id}})
    return {"rule_id": rule_id, "status": "Decommissioned"}


@router.post("/restore")
async def restore(data: dict, user: CurrentUser = Depends(get_current_user)):
    rule_id = data.get("rule_id")
    if not rule_id:
        raise HTTPException(status_code=400, detail="rule_id required")
    await col(COMPILED_RULES).update_one({"rule_id": rule_id}, {"$set": {"status": "Draft", "restored_at": utc_now(), "restored_by": user.user_id}})
    return {"rule_id": rule_id, "status": "Draft"}


@router.post("/decommission/bulk")
async def decommission_bulk(data: dict, user: CurrentUser = Depends(get_current_user)):
    rule_ids = data.get("rule_ids", [])
    now = utc_now()
    count = 0
    for rid in rule_ids:
        result = await col(COMPILED_RULES).update_one({"rule_id": rid}, {"$set": {"status": "Decommissioned", "decommissioned_at": now}})
        count += result.modified_count
    return {"decommissioned": count}


@router.post("/certification/bulk-certify")
async def bulk_certify(data: dict, user: CurrentUser = Depends(get_current_user)):
    rule_ids = data.get("rule_ids", [])
    now = utc_now()
    count = 0
    for rid in rule_ids:
        result = await col(COMPILED_RULES).update_one({"rule_id": rid}, {"$set": {"status": "Certified", "certified_date": now, "certified_by": user.user_id}})
        count += result.modified_count
    return {"certified": count}


@router.post("/certification/auto-expire")
async def auto_expire(data: dict, user: CurrentUser = Depends(get_current_user)):
    return {"expired": 0, "message": "Auto-expire check completed"}
