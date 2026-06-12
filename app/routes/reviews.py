"""Review and approval queue endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional

from app.db.collections import col, REVIEWS
from app.middleware.auth import CurrentUser, get_current_user
from app.models.base import utc_now
from app.services.audit import record_audit

router = APIRouter(prefix="/api/reviews", tags=["Reviews"])


@router.get("")
async def list_reviews(
    status: Optional[str] = Query(None),
    module: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
):
    query: dict = {}
    if status:
        query["status"] = status
    if module:
        query["module"] = module

    cursor = col(REVIEWS).find(query).sort("submitted_at", -1).limit(limit)
    results = await cursor.to_list(length=limit)
    for r in results:
        r.pop("_id", None)
    return results


@router.get("/{review_id}")
async def get_review(review_id: str):
    doc = await col(REVIEWS).find_one({"id": review_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Review not found")
    doc.pop("_id", None)
    return doc


@router.post("")
async def create_review(data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    review_id = data.get("id", f"rev-{uuid.uuid4().hex[:12]}")
    data["id"] = review_id
    data["submitted_at"] = now
    data["status"] = data.get("status", "Pending")
    data["requestor"] = data.get("requestor", user.user_email)
    await col(REVIEWS).insert_one(data)
    await record_audit("reviews", review_id, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


@router.put("/{review_id}")
async def update_review(review_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(REVIEWS).find_one({"id": review_id})
    if not before:
        raise HTTPException(status_code=404, detail="Review not found")
    data["reviewed_at"] = utc_now()
    data["reviewer"] = user.user_email
    data.pop("_id", None)
    await col(REVIEWS).update_one({"id": review_id}, {"$set": data})
    await record_audit("reviews", review_id, "update", user.user_id, user.user_email, user.user_team, before_snapshot=_s(before), after_snapshot=data)
    return {"id": review_id, **data}


def _s(doc: dict | None) -> dict | None:
    if doc is None:
        return None
    d = dict(doc)
    d.pop("_id", None)
    return d
