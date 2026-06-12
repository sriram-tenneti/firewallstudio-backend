"""Firewall group and ingress group CRUD endpoints.

Group member management and change request endpoints are also included.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from typing import Optional

from app.db.collections import col, FIREWALL_GROUPS, INGRESS_GROUPS, REQUESTS
from app.middleware.auth import CurrentUser, get_current_user
from app.models.base import utc_now
from app.services.audit import record_audit

router = APIRouter(prefix="/api/groups", tags=["Firewall Groups"])


# ---- Standard Firewall Groups ----

@router.get("")
async def list_groups(
    app_distributed_id: Optional[str] = Query(None),
    dc_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    limit: int = Query(200, le=1000),
):
    query: dict = {}
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    if dc_id:
        query["dc_id"] = dc_id
    if environment:
        query["environment"] = environment
    if direction:
        query["direction"] = direction

    cursor = col(FIREWALL_GROUPS).find(query).limit(limit)
    results = await cursor.to_list(length=limit)
    for r in results:
        r.pop("_id", None)
    return results


@router.post("")
async def create_group(
    data: dict,
    user: CurrentUser = Depends(get_current_user),
):
    now = utc_now()
    name = data.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail="'name' is required")

    data["_id"] = name
    data.setdefault("group_type", "firewall")
    data["created_at"] = now
    data["created_by"] = user.user_id
    data["updated_at"] = now
    data["updated_by"] = user.user_id

    await col(FIREWALL_GROUPS).insert_one(data)

    await record_audit(
        collection_name="firewall_groups",
        document_id=name,
        operation="create",
        user_id=user.user_id,
        user_email=user.user_email,
        user_team=user.user_team,
        after_snapshot=_strip(data),
        app_distributed_id=data.get("app_distributed_id"),
        module="design-studio",
    )

    data.pop("_id", None)
    return data


# ---- Enhanced Ingress Groups (MUST be before /{group_name} to avoid capture) ----

@router.get("/ingress")
async def list_ingress_groups(
    app_distributed_id: Optional[str] = Query(None),
    dc_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    limit: int = Query(200, le=1000),
):
    query: dict = {"group_type": "ingress"}
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    if dc_id:
        query["dc_id"] = dc_id
    if environment:
        query["environment"] = environment

    cursor = col(INGRESS_GROUPS).find(query).limit(limit)
    results = await cursor.to_list(length=limit)
    for r in results:
        r.pop("_id", None)
    return results


@router.get("/ingress/{group_name}")
async def get_ingress_group(group_name: str):
    doc = await col(INGRESS_GROUPS).find_one({"name": group_name})
    if not doc:
        raise HTTPException(status_code=404, detail="Ingress group not found")
    doc.pop("_id", None)
    return doc


@router.post("/ingress")
async def create_ingress_group(
    data: dict,
    user: CurrentUser = Depends(get_current_user),
):
    now = utc_now()
    name = data.get("name", "")
    if not name:
        raise HTTPException(status_code=400, detail="'name' is required")

    data["_id"] = name
    data["group_type"] = "ingress"
    data["direction"] = "ingress"
    data["created_at"] = now
    data["created_by"] = user.user_id
    data["updated_at"] = now
    data["updated_by"] = user.user_id

    await col(INGRESS_GROUPS).insert_one(data)

    await record_audit(
        collection_name="ingress_groups",
        document_id=name,
        operation="create",
        user_id=user.user_id,
        user_email=user.user_email,
        user_team=user.user_team,
        after_snapshot=_strip(data),
        app_distributed_id=data.get("app_distributed_id"),
        module="design-studio",
    )

    data.pop("_id", None)
    return data


@router.put("/ingress/{group_name}")
async def update_ingress_group(
    group_name: str,
    data: dict,
    user: CurrentUser = Depends(get_current_user),
):
    before = await col(INGRESS_GROUPS).find_one({"name": group_name})
    if not before:
        raise HTTPException(status_code=404, detail="Ingress group not found")

    data["updated_at"] = utc_now()
    data["updated_by"] = user.user_id
    data.pop("_id", None)
    data.pop("name", None)

    await col(INGRESS_GROUPS).update_one({"name": group_name}, {"$set": data})

    await record_audit(
        collection_name="ingress_groups",
        document_id=group_name,
        operation="update",
        user_id=user.user_id,
        user_email=user.user_email,
        user_team=user.user_team,
        before_snapshot=_strip(before),
        after_snapshot=data,
        app_distributed_id=before.get("app_distributed_id"),
        module="design-studio",
    )

    return {"name": group_name, **data}


# ---- Group Change Requests ----

@router.get("/change-requests")
async def list_group_change_requests(
    app_distributed_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
):
    query: dict = {"request_type": "group_change"}
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    if environment:
        query["environment"] = environment
    if status:
        query["status"] = status

    cursor = col(REQUESTS).find(query).sort("created_at", -1).limit(limit)
    results = await cursor.to_list(length=limit)
    for r in results:
        r.pop("_id", None)
    return results


@router.post("/change-requests")
async def create_group_change_request(
    data: dict,
    user: CurrentUser = Depends(get_current_user),
):
    now = utc_now()
    request_id = data.get("request_id", f"GCR-{uuid.uuid4().hex[:8].upper()}")
    data["_id"] = request_id
    data["request_id"] = request_id
    data["request_type"] = "group_change"
    data["status"] = data.get("status", "Draft")
    data["created_at"] = now
    data["created_by"] = user.user_id
    data["updated_at"] = now
    data["updated_by"] = user.user_id

    await col(REQUESTS).insert_one(data)

    await record_audit(
        collection_name="group_change_requests",
        document_id=request_id,
        operation="create",
        user_id=user.user_id,
        user_email=user.user_email,
        user_team=user.user_team,
        after_snapshot=_strip(data),
        app_distributed_id=data.get("app_distributed_id"),
    )

    data.pop("_id", None)
    return data


# ---- Group Member Management ----

@router.get("/{group_name}/members")
async def get_group_members(group_name: str):
    doc = await col(FIREWALL_GROUPS).find_one({"name": group_name})
    if not doc:
        raise HTTPException(status_code=404, detail="Group not found")
    return doc.get("members", [])


@router.post("/{group_name}/members")
async def add_group_member(
    group_name: str,
    data: dict = Body(...),
    user: CurrentUser = Depends(get_current_user),
):
    doc = await col(FIREWALL_GROUPS).find_one({"name": group_name})
    if not doc:
        raise HTTPException(status_code=404, detail="Group not found")

    members = doc.get("members", [])
    members.append(data)

    await col(FIREWALL_GROUPS).update_one(
        {"name": group_name},
        {"$set": {"members": members, "updated_at": utc_now(), "updated_by": user.user_id}},
    )

    return {"message": "Member added", "members": members}


@router.delete("/{group_name}/members/{member_value}")
async def remove_group_member(
    group_name: str,
    member_value: str,
    user: CurrentUser = Depends(get_current_user),
):
    doc = await col(FIREWALL_GROUPS).find_one({"name": group_name})
    if not doc:
        raise HTTPException(status_code=404, detail="Group not found")

    members = [m for m in doc.get("members", []) if m.get("value") != member_value]

    await col(FIREWALL_GROUPS).update_one(
        {"name": group_name},
        {"$set": {"members": members, "updated_at": utc_now(), "updated_by": user.user_id}},
    )

    return {"message": f"Member {member_value} removed", "members": members}


# ---- Single group GET/PUT/DELETE (AFTER all /ingress, /change-requests, /{name}/members) ----

@router.get("/{group_name}")
async def get_group(group_name: str):
    doc = await col(FIREWALL_GROUPS).find_one({"name": group_name})
    if not doc:
        raise HTTPException(status_code=404, detail="Group not found")
    doc.pop("_id", None)
    return doc


@router.put("/{group_name}")
async def update_group(
    group_name: str,
    data: dict,
    user: CurrentUser = Depends(get_current_user),
):
    before = await col(FIREWALL_GROUPS).find_one({"name": group_name})
    if not before:
        raise HTTPException(status_code=404, detail="Group not found")

    data["updated_at"] = utc_now()
    data["updated_by"] = user.user_id
    data.pop("_id", None)
    data.pop("name", None)

    await col(FIREWALL_GROUPS).update_one({"name": group_name}, {"$set": data})

    await record_audit(
        collection_name="firewall_groups",
        document_id=group_name,
        operation="update",
        user_id=user.user_id,
        user_email=user.user_email,
        user_team=user.user_team,
        before_snapshot=_strip(before),
        after_snapshot=data,
        app_distributed_id=before.get("app_distributed_id"),
        module="design-studio",
    )

    return {"name": group_name, **data}


@router.delete("/{group_name}")
async def delete_group(
    group_name: str,
    user: CurrentUser = Depends(get_current_user),
):
    before = await col(FIREWALL_GROUPS).find_one({"name": group_name})
    if not before:
        raise HTTPException(status_code=404, detail="Group not found")

    await col(FIREWALL_GROUPS).delete_one({"name": group_name})

    await record_audit(
        collection_name="firewall_groups",
        document_id=group_name,
        operation="delete",
        user_id=user.user_id,
        user_email=user.user_email,
        user_team=user.user_team,
        before_snapshot=_strip(before),
        app_distributed_id=before.get("app_distributed_id"),
        module="design-studio",
    )

    return {"message": f"Group {group_name} deleted"}


def _strip(doc: dict) -> dict:
    d = dict(doc)
    d.pop("_id", None)
    return d
