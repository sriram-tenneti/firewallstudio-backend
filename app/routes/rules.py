"""Firewall rule CRUD endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional

from app.db.collections import col, RULE_REQUESTS, PHYSICAL_RULES
from app.middleware.auth import CurrentUser, get_current_user
from app.models.base import utc_now
from app.models.rules import RuleRequestCreate, RuleRequestRecord
from app.services.audit import record_audit
from app.services.lifecycle import transition_request_status

router = APIRouter(prefix="/api/rules", tags=["Firewall Rules"])


@router.get("/requests")
async def list_rule_requests(
    app_distributed_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
):
    """List rule requests with optional filters."""
    query: dict = {}
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    if environment:
        query["environment"] = environment
    if status:
        query["status"] = status

    cursor = (
        col(RULE_REQUESTS)
        .find(query)
        .sort("created_at", -1)
        .skip(offset)
        .limit(limit)
    )
    results = await cursor.to_list(length=limit)
    for r in results:
        r.pop("_id", None)
    return results


@router.get("/requests/{request_id}")
async def get_rule_request(request_id: str):
    doc = await col(RULE_REQUESTS).find_one({"request_id": request_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Rule request not found")
    doc.pop("_id", None)
    return doc


@router.post("/requests")
async def create_rule_request(
    data: RuleRequestCreate,
    user: CurrentUser = Depends(get_current_user),
):
    """Submit a new rule request."""
    now = utc_now()
    request_id = f"REQ-{uuid.uuid4().hex[:12]}"
    app_dist_id = data.source_ref or data.application_ref

    doc = {
        "request_id": request_id,
        "app_distributed_id": app_dist_id,
        "source_kind": data.source_kind,
        "source_ref": data.source_ref,
        "application_ref": data.application_ref,
        "destination_kind": data.destination_kind,
        "destination_ref": data.destination_ref,
        "environment": data.environment,
        "ports": data.ports,
        "action": data.action,
        "description": data.description,
        "owner": user.user_email or data.owner,
        "owner_team": user.user_team or data.owner_team,
        "status": "Draft",
        "expansion": [],
        "external_tickets": [],
        "created_at": now,
        "created_by": user.user_id,
        "updated_at": now,
        "updated_by": user.user_id,
    }

    await col(RULE_REQUESTS).insert_one(doc)

    await record_audit(
        collection_name="rule_requests",
        document_id=request_id,
        operation="create",
        user_id=user.user_id,
        user_email=user.user_email,
        user_team=user.user_team,
        after_snapshot=_strip_id(doc),
        app_distributed_id=app_dist_id,
        module="design-studio",
    )

    doc.pop("_id", None)
    return doc


@router.post("/requests/{request_id}/transition")
async def transition_request(
    request_id: str,
    body: dict,
    user: CurrentUser = Depends(get_current_user),
):
    """Transition a rule request to a new status."""
    new_status = body.get("status")
    if not new_status:
        raise HTTPException(status_code=400, detail="'status' is required")

    entry = await transition_request_status(
        request_id=request_id,
        new_status=new_status,
        actor=user.user_id,
        actor_email=user.user_email,
        actor_team=user.user_team,
        module=body.get("module", "design-studio"),
        comments=body.get("comments", ""),
        metadata=body.get("metadata"),
        request_type="rule_request",
    )
    return entry


@router.get("/requests/{request_id}/transitions")
async def get_valid_transitions(request_id: str):
    """Return valid next states for a request."""
    from app.services.lifecycle import get_valid_request_transitions
    transitions = await get_valid_request_transitions(request_id)
    return {"request_id": request_id, "valid_transitions": transitions}


@router.get("/physical")
async def list_physical_rules(
    request_id: Optional[str] = Query(None),
    app_distributed_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
):
    """List physical (per-DC) rules."""
    query: dict = {}
    if request_id:
        query["request_id"] = request_id
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    if environment:
        query["environment"] = environment

    cursor = col(PHYSICAL_RULES).find(query).sort("created_at", -1).limit(limit)
    results = await cursor.to_list(length=limit)
    for r in results:
        r.pop("_id", None)
    return results


def _strip_id(doc: dict) -> dict:
    d = dict(doc)
    d.pop("_id", None)
    return d
