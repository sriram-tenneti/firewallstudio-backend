"""Request tracking endpoints — query request status history.

Serves the new Request Tracking page in the frontend.
"""

from fastapi import APIRouter, Query
from typing import Optional

from app.services.lifecycle import get_request_history

router = APIRouter(prefix="/api/requests", tags=["Request Tracking"])


@router.get("/history")
async def list_request_history(
    app_distributed_id: Optional[str] = Query(None),
    request_id: Optional[str] = Query(None),
    request_type: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
):
    """Query request status transition history.

    Filterable by app_distributed_id, request_id, and request_type.
    Returns newest-first.
    """
    entries = await get_request_history(
        request_id=request_id,
        app_distributed_id=app_distributed_id,
        request_type=request_type,
        limit=limit,
        offset=offset,
    )
    for e in entries:
        e.pop("_id", None)
    return entries
