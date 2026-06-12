"""Firewall rule CRUD endpoints.

Covers:
  - Studio rules (GET /api/rules, GET/POST/PUT/DELETE /api/rules/{id})
  - Rule requests (GET/POST /api/rules/requests, transitions, artifacts)
  - Rule lifecycle (certify, submit, compile, transition, valid-transitions)
  - Physical / compiled rules
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from typing import Optional

from app.db.collections import (
    col, COMPILED_RULES, RULE_REQUESTS, PHYSICAL_RULES,
    REQUEST_STATUS_HISTORY, AUDIT_TRAIL, GROUPS,
)
from app.middleware.auth import CurrentUser, get_current_user
from app.models.base import utc_now
from app.services.audit import record_audit

router = APIRouter(prefix="/api/rules", tags=["Firewall Rules"])


def _strip(doc: dict | None) -> dict | None:
    if doc is None:
        return None
    d = dict(doc)
    d.pop("_id", None)
    return d


def _to_frontend_rule(r: dict) -> dict:
    """Map internal rule schema to the RawBackendRule shape the React frontend expects."""
    src = r.get("source") or r.get("src_group_ref", "")
    dst = r.get("destination") or r.get("dst_group_ref", "")
    ports = r.get("port") or r.get("ports", "")
    proto = r.get("protocol", "")
    if not proto and ports:
        proto = "tcp" if "tcp" in ports.lower() else ("udp" if "udp" in ports.lower() else "tcp")
    src_is_grp = src.startswith("grp-") or src.startswith("g-")
    dst_is_grp = dst.startswith("grp-") or dst.startswith("g-")
    return {
        "rule_id": r.get("rule_id", ""),
        "source": src,
        "source_zone": r.get("source_zone") or r.get("src_sz", ""),
        "destination": dst,
        "destination_zone": r.get("destination_zone") or r.get("dst_sz", ""),
        "port": ports,
        "protocol": proto,
        "action": r.get("action", "permit"),
        "description": r.get("description", ""),
        "application": r.get("application") or r.get("app_distributed_id", ""),
        "status": r.get("status") or r.get("lifecycle_status", "Draft"),
        "is_group_to_group": r.get("is_group_to_group", src_is_grp and dst_is_grp),
        "environment": r.get("environment", ""),
        "datacenter": r.get("datacenter") or r.get("src_dc", ""),
        "created_at": r.get("created_at", ""),
        "updated_at": r.get("updated_at", ""),
        "certified_date": r.get("certified_date") or r.get("certified_at"),
        "expiry_date": r.get("expiry_date") or r.get("expiry"),
    }


# ----------------------------------------------------------------
# Studio Rules — GET /api/rules  (Design Studio main table)
# These are compiled_rules with rule_type != "legacy"
# ----------------------------------------------------------------

@router.get("")
async def list_rules(
    application: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    limit: int = Query(200, le=1000),
):
    query: dict = {"rule_type": {"$ne": "legacy"}}
    if application:
        query["$or"] = [
            {"application": application},
            {"app_id": application},
            {"app_distributed_id": application},
        ]
    if environment:
        query["environment"] = environment

    cursor = col(COMPILED_RULES).find(query).sort("created_at", -1).limit(limit)
    results = await cursor.to_list(length=limit)

    # Post-filter by status if requested (matches either status or lifecycle_status)
    if status:
        sl = status.lower()
        results = [r for r in results if (r.get("status", "") or "").lower() == sl or (r.get("lifecycle_status", "") or "").lower() == sl]

    return [_to_frontend_rule(r) for r in results]


@router.get("/lifecycle/summary")
async def lifecycle_summary():
    all_rules = await col(COMPILED_RULES).find({"rule_type": {"$ne": "legacy"}}).to_list(length=5000)
    status_counts: dict[str, int] = {}
    for r in all_rules:
        s = r.get("status", "Unknown")
        status_counts[s] = status_counts.get(s, 0) + 1
    return {"total": len(all_rules), "by_status": status_counts}


@router.post("/preview-expansion")
async def preview_expansion(data: dict):
    return {
        "request_id": None,
        "expanded_rules": [],
        "dc_summary": {},
        "total_physical_rules": 0,
        "preview": True,
    }


@router.post("/validate")
async def validate_rules(data: dict):
    return {
        "valid": True,
        "errors": [],
        "warnings": [],
        "expanded_rules": [],
        "dc_summary": {},
        "total_physical_rules": 0,
    }


# ---- Rule Requests ----

@router.get("/requests")
async def list_rule_requests(
    app_distributed_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
):
    query: dict = {"request_type": "rule"}
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
    data: dict,
    user: CurrentUser = Depends(get_current_user),
):
    now = utc_now()
    request_id = data.get("request_id", f"REQ-{uuid.uuid4().hex[:12]}")

    data["_id"] = request_id
    data["request_id"] = request_id
    data["request_type"] = "rule"
    data["status"] = data.get("status", "Draft")
    data["created_at"] = now
    data["created_by"] = user.user_id
    data["updated_at"] = now
    data["updated_by"] = user.user_id

    await col(RULE_REQUESTS).insert_one(data)

    await record_audit(
        "rule_requests", request_id, "create",
        user.user_id, user.user_email, user.user_team,
        after_snapshot=_strip(data),
        app_distributed_id=data.get("app_distributed_id"),
        module="design-studio",
    )

    data.pop("_id", None)
    return data


@router.post("/requests/{request_id}/transition")
async def transition_request(
    request_id: str,
    body: dict,
    user: CurrentUser = Depends(get_current_user),
):
    new_status = body.get("status")
    if not new_status:
        raise HTTPException(status_code=400, detail="'status' is required")

    from app.services.lifecycle import transition_request_status
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
async def get_valid_request_transitions(request_id: str):
    from app.services.lifecycle import get_valid_request_transitions
    transitions = await get_valid_request_transitions(request_id)
    return {"request_id": request_id, "valid_transitions": transitions}


# ---- Request Artifacts ----

@router.get("/requests/{request_id}/artifacts")
async def get_request_artifacts(request_id: str, dc_id: Optional[str] = Query(None)):
    return {"request_id": request_id, "dc_id": dc_id, "artifacts": [], "manifest": {}}


@router.get("/requests/{request_id}/artifacts/per-dc")
async def get_request_artifacts_per_dc(request_id: str):
    return {"request_id": request_id, "per_dc": {}}


@router.get("/requests/{request_id}/artifacts/manifest.json")
async def get_request_manifest_json(request_id: str, dc_id: Optional[str] = Query(None)):
    return {"request_id": request_id, "dc_id": dc_id, "rules": [], "groups": [], "summary": {}}


@router.get("/requests/{request_id}/artifacts/manifest.xlsx")
async def get_request_manifest_xlsx(request_id: str, dc_id: Optional[str] = Query(None)):
    return JSONResponse({"detail": "XLSX export not available in JSON mode"}, status_code=501)


@router.get("/requests/{request_id}/artifacts/device.{vendor}")
async def get_request_device_config(request_id: str, vendor: str, dc_id: Optional[str] = Query(None)):
    return {"request_id": request_id, "vendor": vendor, "dc_id": dc_id, "config": ""}


@router.get("/requests/{request_id}/artifacts/bundle.zip")
async def get_request_artifact_bundle(request_id: str, dc_id: Optional[str] = Query(None)):
    return JSONResponse({"detail": "Bundle not available in JSON mode"}, status_code=501)


@router.post("/requests/artifacts/bulk-bundle.zip")
async def get_bulk_artifact_bundle(data: dict):
    return JSONResponse({"detail": "Bulk bundle not available in JSON mode"}, status_code=501)


@router.post("/requests/{request_id}/submit-itsm")
async def submit_to_itsm(request_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    chg_id = f"CHG{str(hash(request_id))[-7:]}"
    return {
        "request_id": request_id,
        "chg_id": chg_id,
        "external_status": "Submitted",
    }


@router.post("/requests/{request_id}/refresh-external-status")
async def refresh_external_status(request_id: str):
    doc = await col(RULE_REQUESTS).find_one({"request_id": request_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Request not found")
    return {
        "request_id": request_id,
        "external_status": doc.get("external_status", "Unknown"),
    }


# ---- Physical (per-DC) rules ----

@router.get("/physical")
async def list_physical_rules(
    request_id: Optional[str] = Query(None),
    app_distributed_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
):
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


# ---- Single rule CRUD (must come after /lifecycle, /requests, /physical, /preview-expansion, /validate) ----

@router.get("/{rule_id}")
async def get_rule(rule_id: str):
    doc = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _to_frontend_rule(doc)


@router.post("")
async def create_rule(data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    rule_id = data.get("rule_id", f"RULE-{uuid.uuid4().hex[:8].upper()}")
    data["_id"] = rule_id
    data["rule_id"] = rule_id
    data.setdefault("rule_type", "compiled")
    data.setdefault("status", "Draft")
    data["created_at"] = now
    data["created_by"] = user.user_id
    data["updated_at"] = now
    data["updated_by"] = user.user_id

    await col(COMPILED_RULES).insert_one(data)
    await record_audit("rules", rule_id, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_strip(data))
    data.pop("_id", None)
    return data


@router.put("/{rule_id}")
async def update_rule(rule_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if not before:
        raise HTTPException(status_code=404, detail="Rule not found")
    data["updated_at"] = utc_now()
    data["updated_by"] = user.user_id
    data.pop("_id", None)
    data.pop("rule_id", None)
    await col(COMPILED_RULES).update_one({"rule_id": rule_id}, {"$set": data})
    await record_audit("rules", rule_id, "update", user.user_id, user.user_email, user.user_team, before_snapshot=_strip(before), after_snapshot=data)
    updated = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if updated:
        updated.pop("_id", None)
    return updated or {"rule_id": rule_id, **data}


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str, user: CurrentUser = Depends(get_current_user)):
    before = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if not before:
        raise HTTPException(status_code=404, detail="Rule not found")
    await col(COMPILED_RULES).delete_one({"rule_id": rule_id})
    await record_audit("rules", rule_id, "delete", user.user_id, user.user_email, user.user_team, before_snapshot=_strip(before))
    return {"message": f"Rule {rule_id} deleted"}


@router.post("/{rule_id}/certify")
async def certify_rule(rule_id: str, user_param: str = Query("System", alias="user"), current_user: CurrentUser = Depends(get_current_user)):
    before = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if not before:
        raise HTTPException(status_code=404, detail="Rule not found")
    now = utc_now()
    update = {"status": "Certified", "certified_date": now, "certified_by": user_param, "updated_at": now}
    await col(COMPILED_RULES).update_one({"rule_id": rule_id}, {"$set": update})
    updated = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if updated:
        updated.pop("_id", None)
    return updated


@router.post("/{rule_id}/submit")
async def submit_rule(rule_id: str, user: CurrentUser = Depends(get_current_user)):
    before = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if not before:
        raise HTTPException(status_code=404, detail="Rule not found")
    now = utc_now()
    await col(COMPILED_RULES).update_one({"rule_id": rule_id}, {"$set": {"status": "Submitted", "updated_at": now}})
    return {"message": f"Rule {rule_id} submitted for review"}


@router.get("/{rule_id}/history")
async def get_rule_history(rule_id: str):
    cursor = col(AUDIT_TRAIL).find({"document_id": rule_id}).sort("timestamp", -1).limit(50)
    results = await cursor.to_list(length=50)
    for r in results:
        r.pop("_id", None)
    return results


@router.post("/{rule_id}/compile")
async def compile_rule(rule_id: str, vendor: str = Query("generic")):
    rule = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.pop("_id", None)
    src = rule.get("source", rule.get("src_group_ref", ""))
    dst = rule.get("destination", rule.get("dst_group_ref", ""))
    port = rule.get("port", rule.get("ports", ""))
    action = rule.get("action", "permit")

    if vendor == "paloalto":
        config = f"set rulebase security rules \"{rule_id}\" from [{rule.get('source_zone', 'any')}] to [{rule.get('destination_zone', 'any')}] source [{src}] destination [{dst}] service [{port}] action {action}"
    elif vendor == "checkpoint":
        config = f"mgmt_cli add access-rule layer \"Network\" position top name \"{rule_id}\" source \"{src}\" destination \"{dst}\" service \"{port}\" action \"{action.title()}\""
    else:
        config = f"# Rule {rule_id}\npermit {src} -> {dst} port {port} action {action}"

    return {
        "rule_id": rule_id,
        "vendor": vendor,
        "config": config,
        "rule": rule,
    }


@router.post("/{rule_id}/lifecycle-transition")
async def lifecycle_transition(rule_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    new_status = data.get("new_status")
    if not new_status:
        raise HTTPException(status_code=400, detail="'new_status' is required")
    before = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if not before:
        raise HTTPException(status_code=404, detail="Rule not found")
    now = utc_now()
    old_status = before.get("status", "Unknown")
    update_doc: dict = {"status": new_status, "updated_at": now, "updated_by": user.user_id}
    if new_status == "Certified":
        update_doc["certified_date"] = now
    if new_status == "Deployed":
        update_doc["deployed_at"] = now
    await col(COMPILED_RULES).update_one({"rule_id": rule_id}, {"$set": update_doc})

    await col(REQUEST_STATUS_HISTORY).insert_one({
        "rule_id": rule_id,
        "from_status": old_status,
        "to_status": new_status,
        "actor": user.user_id,
        "module": data.get("module", "studio"),
        "timestamp": now,
    })

    updated = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if updated:
        updated.pop("_id", None)
    return updated


@router.get("/{rule_id}/valid-transitions")
async def valid_transitions(rule_id: str):
    rule = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    current = rule.get("status", "Draft")
    transitions_map = {
        "Draft": ["Submitted"],
        "Submitted": ["In Progress", "Approved", "Rejected"],
        "In Progress": ["Approved", "Rejected"],
        "Approved": ["Deployed", "Rejected"],
        "Deployed": ["Certified", "Decommissioned"],
        "Certified": ["Expired", "Decommissioned"],
        "Rejected": ["Draft"],
        "Expired": ["Draft"],
        "Decommissioned": [],
    }
    return {
        "rule_id": rule_id,
        "current_status": current,
        "valid_transitions": transitions_map.get(current, []),
    }
