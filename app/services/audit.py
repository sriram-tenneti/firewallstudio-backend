"""Audit trail recording service.

Records every data mutation into the audit_trail collection.
"""

import uuid
from typing import Optional

from app.db.collections import col, AUDIT_TRAIL
from app.models.base import utc_now


async def record_audit(
    collection_name: str,
    document_id: str,
    operation: str,
    user_id: str = "system",
    user_email: str = "",
    user_team: str = "",
    before_snapshot: Optional[dict] = None,
    after_snapshot: Optional[dict] = None,
    changed_fields: Optional[list[str]] = None,
    app_distributed_id: Optional[str] = None,
    ip_address: str = "",
    request_id: str = "",
    module: str = "",
) -> dict:
    """Write an audit trail entry.

    Called by the audit middleware and directly by services
    that need more control over the before/after snapshots.
    """
    entry = {
        "_id": f"AUD-{uuid.uuid4().hex[:12]}",
        "app_distributed_id": app_distributed_id,
        "collection": collection_name,
        "document_id": str(document_id),
        "operation": operation,
        "user_id": user_id,
        "user_email": user_email,
        "user_team": user_team,
        "timestamp": utc_now(),
        "before_snapshot": before_snapshot,
        "after_snapshot": after_snapshot,
        "changed_fields": changed_fields or [],
        "ip_address": ip_address,
        "request_id": request_id,
        "module": module,
    }
    await col(AUDIT_TRAIL).insert_one(entry)
    return entry


async def get_audit_entries(
    app_distributed_id: Optional[str] = None,
    collection_name: Optional[str] = None,
    document_id: Optional[str] = None,
    user_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Query audit trail with optional filters."""
    query: dict = {}
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    if collection_name:
        query["collection"] = collection_name
    if document_id:
        query["document_id"] = document_id
    if user_id:
        query["user_id"] = user_id

    cursor = (
        col(AUDIT_TRAIL)
        .find(query)
        .sort("timestamp", -1)
        .skip(offset)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)
