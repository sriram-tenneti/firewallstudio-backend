"""Audit trail query endpoints."""

from fastapi import APIRouter, Query
from typing import Optional

from app.services.audit import get_audit_entries

router = APIRouter(prefix="/api/audit", tags=["Audit Trail"])


@router.get("")
async def list_audit_entries(
    app_distributed_id: Optional[str] = Query(None),
    collection: Optional[str] = Query(None),
    document_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
):
    """Query the audit trail with optional filters.

    All entries are ordered newest-first.
    """
    entries = await get_audit_entries(
        app_distributed_id=app_distributed_id,
        collection_name=collection,
        document_id=document_id,
        user_id=user_id,
        limit=limit,
        offset=offset,
    )
    for e in entries:
        e.pop("_id", None)
    return entries
