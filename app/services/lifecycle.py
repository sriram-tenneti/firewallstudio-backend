"""Request status tracking and lifecycle state machine service.

Manages state transitions for rule requests, group change requests,
and records every transition into the request_status_history collection.
"""

import uuid

from fastapi import HTTPException

from app.db.collections import col, RULE_REQUESTS, REQUEST_STATUS_HISTORY, GROUP_CHANGE_REQUESTS
from app.models.base import utc_now
from app.models.requests import (
    is_valid_transition,
    get_valid_transitions,
    REQUEST_STATE_MACHINE,
    GROUP_REQUEST_STATE_MACHINE,
)
from app.services.audit import record_audit


# Lifecycle event types for structured audit
EVENT_TYPES = [
    "created", "submitted", "approved", "rejected",
    "deployed", "certified", "expired", "decommission_requested",
    "decommissioned", "soft_deleted", "restored",
    "modified", "migrated", "comment", "bulk_action",
    "recertified", "ownership_changed",
]


async def transition_request_status(
    request_id: str,
    new_status: str,
    actor: str = "system",
    actor_email: str = "",
    actor_team: str = "",
    module: str = "design-studio",
    comments: str = "",
    metadata: dict | None = None,
    request_type: str = "rule_request",
) -> dict:
    """Transition a request to a new status.

    Validates the transition against the state machine, updates the
    request document, and records in request_status_history.
    """
    # Determine collection and fetch
    if request_type == "group_change":
        coll = col(GROUP_CHANGE_REQUESTS)
    else:
        coll = col(RULE_REQUESTS)

    doc = await coll.find_one({"request_id": request_id})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Request {request_id} not found")

    current_status = doc.get("status", "Draft")
    is_legacy = doc.get("_is_legacy", False)

    if not is_valid_transition(current_status, new_status, is_legacy, request_type):
        valid = get_valid_transitions(current_status, is_legacy, request_type)
        raise HTTPException(
            status_code=400,
            detail=f"Invalid transition: {current_status} → {new_status}. "
                   f"Valid: {valid}",
        )

    now = utc_now()
    app_distributed_id = doc.get("app_distributed_id", "")

    # Update the request document
    before = dict(doc)
    await coll.update_one(
        {"request_id": request_id},
        {"$set": {"status": new_status, "updated_at": now, "updated_by": actor}},
    )

    # Record in request_status_history
    history_entry = {
        "_id": f"RSH-{uuid.uuid4().hex[:12]}",
        "app_distributed_id": app_distributed_id,
        "request_id": request_id,
        "request_type": request_type,
        "from_status": current_status,
        "to_status": new_status,
        "transitioned_at": now,
        "transitioned_by": actor_email or actor,
        "module": module,
        "comments": comments,
        "metadata": metadata or {},
    }
    await col(REQUEST_STATUS_HISTORY).insert_one(history_entry)

    # Record audit trail
    await record_audit(
        collection_name="rule_requests" if request_type != "group_change" else "group_change_requests",
        document_id=request_id,
        operation="update",
        user_id=actor,
        user_email=actor_email,
        user_team=actor_team,
        before_snapshot=_sanitize(before),
        after_snapshot={"status": new_status},
        changed_fields=["status", "updated_at", "updated_by"],
        app_distributed_id=app_distributed_id,
        module=module,
    )

    return history_entry


async def get_request_history(
    request_id: str | None = None,
    app_distributed_id: str | None = None,
    request_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Query request status history."""
    query: dict = {}
    if request_id:
        query["request_id"] = request_id
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    if request_type:
        query["request_type"] = request_type

    cursor = (
        col(REQUEST_STATUS_HISTORY)
        .find(query)
        .sort("transitioned_at", -1)
        .skip(offset)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)


async def get_valid_request_transitions(request_id: str, request_type: str = "rule_request") -> list[str]:
    """Return valid next states for a request."""
    if request_type == "group_change":
        coll = col(GROUP_CHANGE_REQUESTS)
    else:
        coll = col(RULE_REQUESTS)

    doc = await coll.find_one({"request_id": request_id})
    if not doc:
        return []

    current_status = doc.get("status", "Draft")
    is_legacy = doc.get("_is_legacy", False)
    return get_valid_transitions(current_status, is_legacy, request_type)


def _sanitize(doc: dict) -> dict:
    """Remove ObjectId for JSON serialization."""
    d = dict(doc)
    d.pop("_id", None)
    return d
