"""Reference data CRUD endpoints — NHs, SZs, DCs, Apps, Policy Matrix, Groups, etc.

Covers all /api/reference/* endpoints expected by the frontend.
"""

import uuid
import re

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File as FileParam
from typing import Optional

from app.db.collections import (
    col,
    APPLICATIONS, APP_PRESENCES,
    SHARED_SERVICES, SHARED_SERVICE_PRESENCES,
    NEIGHBOURHOODS, SECURITY_ZONES,
    NGDC_DATACENTERS, LEGACY_DATACENTERS,
    ENVIRONMENTS, POLICY_MATRIX,
    NAMING_STANDARDS, PORT_CATALOG,
    ORG_CONFIG, APP_DC_MAPPINGS,
    COMPILED_RULES, REFERENCE_DATA,
    GROUPS, REQUESTS, REVIEWS,
    MIGRATIONS, AUDIT_TRAIL,
)
from app.middleware.auth import CurrentUser, get_current_user
from app.models.base import utc_now
from app.services.audit import record_audit

router = APIRouter(prefix="/api/reference", tags=["Reference Data"])


# ---- Generic helpers ----

async def _list_col(collection: str, query: dict, limit: int = 500) -> list:
    cursor = col(collection).find(query).limit(limit)
    results = await cursor.to_list(length=limit)
    for r in results:
        r.pop("_id", None)
    return results


async def _get_one(collection: str, filter_dict: dict) -> dict:
    doc = await col(collection).find_one(filter_dict)
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    doc.pop("_id", None)
    return doc


def _s(doc: dict | None) -> dict | None:
    if doc is None:
        return None
    d = dict(doc)
    d.pop("_id", None)
    return d


# ---- Applications ----

@router.get("/applications")
async def list_applications(
    team: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
):
    query: dict = {}
    if team:
        query["owner_team"] = team
    if environment:
        query["environment"] = environment
    return await _list_col(APPLICATIONS, query)


@router.get("/applications/{app_distributed_id}")
async def get_application(app_distributed_id: str):
    return await _get_one(APPLICATIONS, {"app_distributed_id": app_distributed_id})


@router.post("/applications")
async def create_application(data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    app_id = data.get("app_distributed_id", "")
    data["_id"] = app_id
    data["created_at"] = now
    data["created_by"] = user.user_id
    data["updated_at"] = now
    data["updated_by"] = user.user_id
    await col(APPLICATIONS).insert_one(data)
    await record_audit("applications", app_id, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data), app_distributed_id=app_id)
    data.pop("_id", None)
    return data


@router.put("/applications/{app_distributed_id}")
async def update_application(app_distributed_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(APPLICATIONS).find_one({"app_distributed_id": app_distributed_id})
    if not before:
        raise HTTPException(status_code=404, detail="Application not found")
    data["updated_at"] = utc_now()
    data["updated_by"] = user.user_id
    data.pop("_id", None)
    await col(APPLICATIONS).update_one({"app_distributed_id": app_distributed_id}, {"$set": data})
    await record_audit("applications", app_distributed_id, "update", user.user_id, user.user_email, user.user_team, before_snapshot=_s(before), after_snapshot=data, app_distributed_id=app_distributed_id)
    return {"app_distributed_id": app_distributed_id, **data}


@router.delete("/applications/{app_distributed_id}")
async def delete_application(app_distributed_id: str, user: CurrentUser = Depends(get_current_user)):
    before = await col(APPLICATIONS).find_one({"app_distributed_id": app_distributed_id})
    if not before:
        raise HTTPException(status_code=404, detail="Application not found")
    await col(APPLICATIONS).delete_one({"app_distributed_id": app_distributed_id})
    await record_audit("applications", app_distributed_id, "delete", user.user_id, user.user_email, user.user_team, before_snapshot=_s(before), app_distributed_id=app_distributed_id)
    return {"message": f"Application {app_distributed_id} deleted"}


@router.delete("/applications/clear")
async def clear_all_applications(user: CurrentUser = Depends(get_current_user)):
    result = await col(APPLICATIONS).delete_many({})
    return {"message": "All applications cleared", "deleted": result.deleted_count}


# ---- App Presences ----

@router.get("/app-presences")
async def list_app_presences(
    app_distributed_id: Optional[str] = Query(None),
    dc_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
):
    query: dict = {}
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    if dc_id:
        query["dc_id"] = dc_id
    if environment:
        query["environment"] = environment
    return await _list_col(APP_PRESENCES, query)


@router.post("/app-presences")
async def create_app_presence(data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    data["created_at"] = now
    data["created_by"] = user.user_id
    data["updated_at"] = now
    data["updated_by"] = user.user_id
    result = await col(APP_PRESENCES).insert_one(data)
    doc_id = str(result.inserted_id)
    await record_audit("app_presences", doc_id, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data), app_distributed_id=data.get("app_distributed_id"))
    data.pop("_id", None)
    return data


# ---- App DC Mappings ----

@router.get("/app-dc-mappings")
async def list_app_dc_mappings(app_distributed_id: Optional[str] = Query(None)):
    query: dict = {"ref_type": "app_dc_mapping"}
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    return await _list_col(APP_DC_MAPPINGS, query)


@router.post("/app-dc-mappings")
async def create_app_dc_mapping(data: dict, user: CurrentUser = Depends(get_current_user)):
    data["ref_type"] = "app_dc_mapping"
    result = await col(APP_DC_MAPPINGS).insert_one(data)
    data.pop("_id", None)
    return data


@router.post("/app-dc-mappings/bulk")
async def bulk_create_app_dc_mappings(data: dict, user: CurrentUser = Depends(get_current_user)):
    mappings = data.get("mappings", [])
    for m in mappings:
        m["ref_type"] = "app_dc_mapping"
    if mappings:
        await col(APP_DC_MAPPINGS).insert_many(mappings)
    return {"created": len(mappings)}


@router.post("/app-lifecycle-transition")
async def app_lifecycle_transition(data: dict, user: CurrentUser = Depends(get_current_user)):
    app_id = data.get("app_distributed_id")
    new_status = data.get("new_status")
    if not app_id or not new_status:
        raise HTTPException(status_code=400, detail="app_distributed_id and new_status required")
    await col(APPLICATIONS).update_one({"app_distributed_id": app_id}, {"$set": {"status": new_status, "updated_at": utc_now()}})
    return {"app_distributed_id": app_id, "status": new_status}


@router.get("/app-migration-summary")
async def app_migration_summary(app_distributed_id: Optional[str] = Query(None)):
    query: dict = {"rule_type": "legacy"}
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    rules = await col(COMPILED_RULES).find(query).to_list(length=5000)
    total = len(rules)
    migrated = sum(1 for r in rules if r.get("migration_status") == "migrated")
    pending = sum(1 for r in rules if r.get("migration_status") == "pending")
    in_progress = sum(1 for r in rules if r.get("migration_status") == "in_progress")
    return {"total": total, "migrated": migrated, "pending": pending, "in_progress": in_progress}


# ---- Shared Services ----

@router.get("/shared-services")
async def list_shared_services(team: Optional[str] = Query(None)):
    query: dict = {}
    if team:
        query["owner_team"] = team
    return await _list_col(SHARED_SERVICES, query)


@router.get("/shared-services/{service_id}")
async def get_shared_service(service_id: str):
    return await _get_one(SHARED_SERVICES, {"service_id": service_id})


@router.post("/shared-services")
async def create_shared_service(data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    sid = data.get("service_id", "")
    data["_id"] = sid
    data["created_at"] = now
    data["created_by"] = user.user_id
    data["updated_at"] = now
    data["updated_by"] = user.user_id
    await col(SHARED_SERVICES).insert_one(data)
    await record_audit("shared_services", sid, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


@router.put("/shared-services/{service_id}")
async def update_shared_service(service_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(SHARED_SERVICES).find_one({"service_id": service_id})
    if not before:
        raise HTTPException(status_code=404, detail="Shared service not found")
    data["updated_at"] = utc_now()
    data["updated_by"] = user.user_id
    data.pop("_id", None)
    await col(SHARED_SERVICES).update_one({"service_id": service_id}, {"$set": data})
    await record_audit("shared_services", service_id, "update", user.user_id, user.user_email, user.user_team, before_snapshot=_s(before), after_snapshot=data)
    return {"service_id": service_id, **data}


@router.get("/shared-service-presences")
async def list_shared_service_presences(
    service_id: Optional[str] = Query(None),
    dc_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
):
    query: dict = {}
    if service_id:
        query["service_id"] = service_id
    if dc_id:
        query["dc_id"] = dc_id
    if environment:
        query["environment"] = environment
    return await _list_col(SHARED_SERVICE_PRESENCES, query)


# ---- Neighbourhoods ----

@router.get("/neighbourhoods")
async def list_neighbourhoods():
    return await _list_col(NEIGHBOURHOODS, {"ref_type": "neighbourhood"})


@router.post("/neighbourhoods")
async def create_neighbourhood(data: dict, user: CurrentUser = Depends(get_current_user)):
    nh_id = data.get("nh_id", "")
    data["_id"] = nh_id
    data["ref_type"] = "neighbourhood"
    await col(NEIGHBOURHOODS).insert_one(data)
    await record_audit("neighbourhoods", nh_id, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


@router.put("/neighbourhoods/{nh_id}")
async def update_neighbourhood(nh_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(NEIGHBOURHOODS).find_one({"nh_id": nh_id, "ref_type": "neighbourhood"})
    if not before:
        raise HTTPException(status_code=404, detail="Neighbourhood not found")
    data.pop("_id", None)
    await col(NEIGHBOURHOODS).update_one({"nh_id": nh_id, "ref_type": "neighbourhood"}, {"$set": data})
    return {"nh_id": nh_id, **data}


@router.delete("/neighbourhoods/{nh_id}")
async def delete_neighbourhood(nh_id: str, user: CurrentUser = Depends(get_current_user)):
    await col(NEIGHBOURHOODS).delete_one({"nh_id": nh_id, "ref_type": "neighbourhood"})
    return {"message": f"Neighbourhood {nh_id} deleted"}


# ---- Security Zones ----

@router.get("/security-zones")
async def list_security_zones():
    return await _list_col(SECURITY_ZONES, {"ref_type": "security_zone"})


@router.post("/security-zones")
async def create_security_zone(data: dict, user: CurrentUser = Depends(get_current_user)):
    code = data.get("sz_code", data.get("code", ""))
    data["_id"] = code
    data["ref_type"] = "security_zone"
    await col(SECURITY_ZONES).insert_one(data)
    await record_audit("security_zones", code, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


@router.put("/security-zones/{code}")
async def update_security_zone(code: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    q = {"$or": [{"sz_code": code}, {"code": code}], "ref_type": "security_zone"}
    before = await col(SECURITY_ZONES).find_one(q)
    if not before:
        raise HTTPException(status_code=404, detail="Security zone not found")
    data.pop("_id", None)
    await col(SECURITY_ZONES).update_one({"_id": before["_id"]}, {"$set": data})
    return {"code": code, **data}


@router.delete("/security-zones/{code}")
async def delete_security_zone(code: str, user: CurrentUser = Depends(get_current_user)):
    await col(SECURITY_ZONES).delete_one({"$or": [{"sz_code": code}, {"code": code}], "ref_type": "security_zone"})
    return {"message": f"Security zone {code} deleted"}


# ---- SZ CIDR Map/Bindings ----

@router.get("/sz-cidr-map")
async def get_sz_cidr_map():
    return await _list_col(REFERENCE_DATA, {"ref_type": "sz_cidr_map"})


@router.get("/sz-cidr-bindings")
async def get_sz_cidr_bindings():
    return await _list_col(REFERENCE_DATA, {"ref_type": "sz_cidr_binding"})


# ---- Data Centers ----

@router.get("/datacenters/ngdc")
async def list_ngdc_datacenters_path():
    return await _list_col(NGDC_DATACENTERS, {"ref_type": "ngdc_datacenter"})


@router.get("/datacenters/legacy")
async def list_legacy_datacenters_path():
    return await _list_col(LEGACY_DATACENTERS, {"ref_type": "legacy_datacenter"})


@router.get("/ngdc-datacenters")
async def list_ngdc_datacenters():
    return await _list_col(NGDC_DATACENTERS, {"ref_type": "ngdc_datacenter"})


@router.post("/ngdc-datacenters")
async def create_ngdc_datacenter(data: dict, user: CurrentUser = Depends(get_current_user)):
    data["ref_type"] = "ngdc_datacenter"
    dc_id = data.get("dc_id", "")
    data["_id"] = dc_id
    await col(NGDC_DATACENTERS).insert_one(data)
    data.pop("_id", None)
    return data


@router.put("/ngdc-datacenters/{code}")
async def update_ngdc_datacenter(code: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(NGDC_DATACENTERS).find_one({"dc_id": code, "ref_type": "ngdc_datacenter"})
    if not before:
        raise HTTPException(status_code=404, detail="NGDC datacenter not found")
    data.pop("_id", None)
    await col(NGDC_DATACENTERS).update_one({"dc_id": code, "ref_type": "ngdc_datacenter"}, {"$set": data})
    return {"dc_id": code, **data}


@router.delete("/ngdc-datacenters/{code}")
async def delete_ngdc_datacenter(code: str, user: CurrentUser = Depends(get_current_user)):
    await col(NGDC_DATACENTERS).delete_one({"dc_id": code, "ref_type": "ngdc_datacenter"})
    return {"message": f"NGDC datacenter {code} deleted"}


@router.get("/legacy-datacenters")
async def list_legacy_datacenters():
    return await _list_col(LEGACY_DATACENTERS, {"ref_type": "legacy_datacenter"})


@router.post("/legacy-datacenters")
async def create_legacy_datacenter(data: dict, user: CurrentUser = Depends(get_current_user)):
    data["ref_type"] = "legacy_datacenter"
    dc_id = data.get("dc_id", data.get("code", ""))
    data["_id"] = dc_id
    await col(LEGACY_DATACENTERS).insert_one(data)
    data.pop("_id", None)
    return data


@router.put("/legacy-datacenters/{code}")
async def update_legacy_datacenter(code: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(LEGACY_DATACENTERS).find_one({"$or": [{"dc_id": code}, {"code": code}], "ref_type": "legacy_datacenter"})
    if not before:
        raise HTTPException(status_code=404, detail="Legacy datacenter not found")
    data.pop("_id", None)
    await col(LEGACY_DATACENTERS).update_one({"_id": before["_id"]}, {"$set": data})
    return {"code": code, **data}


@router.delete("/legacy-datacenters/{code}")
async def delete_legacy_datacenter(code: str, user: CurrentUser = Depends(get_current_user)):
    await col(LEGACY_DATACENTERS).delete_one({"$or": [{"dc_id": code}, {"code": code}], "ref_type": "legacy_datacenter"})
    return {"message": f"Legacy datacenter {code} deleted"}


# ---- Environments ----

@router.get("/environments")
async def list_environments():
    envs = await _list_col(ENVIRONMENTS, {"ref_type": "environment"})
    if not envs:
        return ["Production", "Non-Production", "Pre-Production"]
    return envs


@router.post("/environments")
async def create_environment(data: dict, user: CurrentUser = Depends(get_current_user)):
    data["ref_type"] = "environment"
    await col(ENVIRONMENTS).insert_one(data)
    data.pop("_id", None)
    return data


@router.delete("/environments/{code}")
async def delete_environment(code: str, user: CurrentUser = Depends(get_current_user)):
    await col(ENVIRONMENTS).delete_one({"$or": [{"code": code}, {"name": code}], "ref_type": "environment"})
    return {"message": f"Environment {code} deleted"}


# ---- Predefined Destinations ----

@router.get("/predefined-destinations")
async def list_predefined_destinations():
    return await _list_col(REFERENCE_DATA, {"ref_type": "predefined_destination"})


@router.post("/predefined-destinations")
async def create_predefined_destination(data: dict, user: CurrentUser = Depends(get_current_user)):
    data["ref_type"] = "predefined_destination"
    await col(REFERENCE_DATA).insert_one(data)
    data.pop("_id", None)
    return data


@router.put("/predefined-destinations/{name}")
async def update_predefined_destination(name: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(REFERENCE_DATA).find_one({"name": name, "ref_type": "predefined_destination"})
    if not before:
        raise HTTPException(status_code=404, detail="Predefined destination not found")
    data.pop("_id", None)
    await col(REFERENCE_DATA).update_one({"_id": before["_id"]}, {"$set": data})
    return {"name": name, **data}


@router.delete("/predefined-destinations/{name}")
async def delete_predefined_destination(name: str, user: CurrentUser = Depends(get_current_user)):
    await col(REFERENCE_DATA).delete_one({"name": name, "ref_type": "predefined_destination"})
    return {"message": f"Predefined destination {name} deleted"}


# ---- Policy Matrix ----

@router.get("/policy-matrix")
async def list_policy_matrix():
    return await _list_col(POLICY_MATRIX, {"ref_type": "policy_matrix"}, limit=1000)


@router.get("/policy-matrix/all")
async def list_all_policy_matrix():
    return await _list_col(POLICY_MATRIX, {"ref_type": "policy_matrix"}, limit=5000)


@router.get("/policy-matrix/ngdc-prod")
async def list_policy_matrix_ngdc_prod():
    return await _list_col(POLICY_MATRIX, {"ref_type": "policy_matrix", "environment": "Production"})


@router.get("/policy-matrix/nonprod")
async def list_policy_matrix_nonprod():
    return await _list_col(POLICY_MATRIX, {"ref_type": "policy_matrix", "environment": "Non-Production"})


@router.get("/policy-matrix/preprod")
async def list_policy_matrix_preprod():
    return await _list_col(POLICY_MATRIX, {"ref_type": "policy_matrix", "environment": "Pre-Production"})


@router.post("/policy-matrix")
async def create_policy_entry(data: dict, user: CurrentUser = Depends(get_current_user)):
    data["ref_type"] = "policy_matrix"
    result = await col(POLICY_MATRIX).insert_one(data)
    await record_audit("policy_matrix", str(result.inserted_id), "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


@router.put("/policy-matrix/{source_zone}/{dest_zone}")
async def update_policy_entry(source_zone: str, dest_zone: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    q = {"source_zone": source_zone, "destination_zone": dest_zone, "ref_type": "policy_matrix"}
    before = await col(POLICY_MATRIX).find_one(q)
    if not before:
        raise HTTPException(status_code=404, detail="Policy entry not found")
    data.pop("_id", None)
    await col(POLICY_MATRIX).update_one(q, {"$set": data})
    return data


@router.delete("/policy-matrix/{source_zone}/{dest_zone}")
async def delete_policy_entry(source_zone: str, dest_zone: str, user: CurrentUser = Depends(get_current_user)):
    q = {"source_zone": source_zone, "destination_zone": dest_zone, "ref_type": "policy_matrix"}
    await col(POLICY_MATRIX).delete_one(q)
    return {"message": f"Policy entry {source_zone}->{dest_zone} deleted"}


# ---- Policy Changes ----

@router.get("/policy-changes")
async def list_policy_changes(status: Optional[str] = Query(None)):
    query: dict = {"ref_type": "policy_change"}
    if status:
        query["status"] = status
    return await _list_col(REFERENCE_DATA, query)


@router.post("/policy-changes")
async def submit_policy_change(data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    change_id = f"PC-{uuid.uuid4().hex[:8].upper()}"
    data["_id"] = change_id
    data["change_id"] = change_id
    data["ref_type"] = "policy_change"
    data["status"] = "Pending"
    data["created_at"] = now
    data["created_by"] = user.user_id
    await col(REFERENCE_DATA).insert_one(data)
    data.pop("_id", None)
    return data


@router.post("/policy-changes/{change_id}/approve")
async def approve_policy_change(change_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    await col(REFERENCE_DATA).update_one({"change_id": change_id}, {"$set": {"status": "Approved", "approved_at": utc_now(), "approved_by": user.user_id}})
    return {"change_id": change_id, "status": "Approved"}


@router.post("/policy-changes/{change_id}/reject")
async def reject_policy_change(change_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    await col(REFERENCE_DATA).update_one({"change_id": change_id}, {"$set": {"status": "Rejected", "rejected_at": utc_now(), "rejected_by": user.user_id, "notes": data.get("notes", "")}})
    return {"change_id": change_id, "status": "Rejected"}


# ---- Naming Standards ----

@router.get("/naming-standards")
async def get_naming_standards():
    results = await _list_col(NAMING_STANDARDS, {"ref_type": "naming_standard"}, limit=100)
    if results:
        return results
    return {
        "patterns": {
            "group": {"NGDC": "grp-{APP}-{COMP}-{NH}-{SZ}", "Legacy": "g-{name}"},
            "server": {"NGDC": "svr-{APP}-{FUNC}-{NH}-{SZ}"},
            "range": {"NGDC": "rng-{APP}-{SUBNET}-{NH}-{SZ}"},
        }
    }


@router.put("/naming-standards")
async def update_naming_standards(data: dict, user: CurrentUser = Depends(get_current_user)):
    data["ref_type"] = "naming_standard"
    existing = await col(NAMING_STANDARDS).find_one({"ref_type": "naming_standard"})
    if existing:
        await col(NAMING_STANDARDS).replace_one({"_id": existing["_id"]}, data)
    else:
        await col(NAMING_STANDARDS).insert_one(data)
    data.pop("_id", None)
    return data


@router.post("/naming-standards/validate")
async def validate_naming(data: dict):
    name = data.get("name", "")
    ngdc_group = re.match(r'^grp-(\w+)-(\w+)-(\w+)-(\w+)$', name)
    ngdc_server = re.match(r'^svr-(\w+)-(\w+)-(\w+)-(\w+)$', name)
    ngdc_range = re.match(r'^rng-(\w+)-(\w+)-(\w+)-(\w+)$', name)
    legacy_group = re.match(r'^g-(.+)$', name)

    if ngdc_group:
        return {"valid": True, "parsed": {"type": "group", "app": ngdc_group.group(1), "comp": ngdc_group.group(2), "nh": ngdc_group.group(3), "sz": ngdc_group.group(4)}}
    if ngdc_server:
        return {"valid": True, "parsed": {"type": "server", "app": ngdc_server.group(1), "func": ngdc_server.group(2), "nh": ngdc_server.group(3), "sz": ngdc_server.group(4)}}
    if ngdc_range:
        return {"valid": True, "parsed": {"type": "range", "app": ngdc_range.group(1), "subnet": ngdc_range.group(2), "nh": ngdc_range.group(3), "sz": ngdc_range.group(4)}}
    if legacy_group:
        return {"valid": True, "parsed": {"type": "legacy_group", "name": legacy_group.group(1)}}
    return {"valid": False, "error": "Name does not match any known naming pattern"}


@router.post("/naming-standards/generate")
async def generate_name(data: dict):
    name_type = data.get("type", "group")
    app_id = data.get("app_id", "APP")
    nh = data.get("nh", "NH")
    sz = data.get("sz", "SZ")
    subtype = data.get("subtype", "WEB")
    prefix = {"group": "grp", "server": "svr", "subnet": "rng"}.get(name_type, "grp")
    return {"name": f"{prefix}-{app_id}-{subtype}-{nh}-{sz}"}


@router.post("/naming-standards/suggest")
async def suggest_standard_name(data: dict):
    legacy_name = data.get("legacy_name", "")
    app_id = data.get("app_id", "APP")
    nh = data.get("nh", "NH")
    sz = data.get("sz", "SZ")
    comp = legacy_name.replace("g-", "").replace("grp-", "").split("-")[0].upper() if legacy_name else "GEN"
    return {"suggested_name": f"grp-{app_id}-{comp}-{nh}-{sz}", "confidence": "medium"}


@router.post("/naming-standards/determine-zone")
async def determine_zone(data: dict):
    if data.get("pci_pan") or data.get("pci_track_data") or data.get("pci_cvv_pin"):
        return {"zone": "CDE", "zone_name": "Cardholder Data Env", "reasoning": ["PCI data present"]}
    if data.get("paa_zone"):
        return {"zone": "PAA", "zone_name": "PCI Account Area", "reasoning": ["PAA zone selected"]}
    if data.get("exposure") == "internet":
        return {"zone": "3PY", "zone_name": "Third Party", "reasoning": ["Internet-facing"]}
    return {"zone": "GEN", "zone_name": "General", "reasoning": ["Default zone"]}


# ---- Port Catalog ----

@router.get("/port-catalog")
async def list_port_catalog():
    return await _list_col(PORT_CATALOG, {"ref_type": "port_catalog"})


# ---- Org Config ----

@router.get("/org-config")
async def get_org_config():
    doc = await col(ORG_CONFIG).find_one({"ref_type": "org_config"})
    if doc:
        doc.pop("_id", None)
    return doc or {}


@router.put("/org-config")
async def update_org_config(data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(ORG_CONFIG).find_one({"ref_type": "org_config"})
    data["ref_type"] = "org_config"
    if before:
        data.pop("_id", None)
        await col(ORG_CONFIG).replace_one({"_id": before["_id"]}, data)
    else:
        await col(ORG_CONFIG).insert_one(data)
    await record_audit("org_config", "org_config", "update", user.user_id, user.user_email, user.user_team, before_snapshot=_s(before) if before else None, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


# ---- CHG Requests ----

@router.get("/chg-requests")
async def list_chg_requests():
    return await _list_col(SHARED_SERVICES, {"service_type": "chg_request"})


# ---- Hide Seed / Data Mode ----

_hide_seed_flag = {"value": False}
_data_mode = {"mode": "seed"}


@router.get("/hide-seed")
async def get_hide_seed():
    return {"hide_seed": _hide_seed_flag["value"]}


@router.post("/hide-seed")
async def set_hide_seed(data: dict):
    _hide_seed_flag["value"] = data.get("hide", False)
    return {"hide_seed": _hide_seed_flag["value"]}


@router.get("/data-mode")
async def get_data_mode():
    return {"mode": _data_mode["mode"]}


@router.post("/data-mode")
async def set_data_mode(data: dict):
    _data_mode["mode"] = data.get("mode", "seed")
    return {"mode": _data_mode["mode"]}


@router.post("/data-mode/reset-seed")
async def reset_seed():
    from app.db.store import get_store, JsonFileStore
    store = get_store()
    if isinstance(store, JsonFileStore):
        counts = await store.load_from_files()
        return {"message": "Seed data reloaded", "counts": counts}
    return {"message": "Reset only available in JSON mode"}


# ---- Real Data (non-seed) ----

@router.get("/rules/real")
async def get_real_rules():
    rules = await _list_col(COMPILED_RULES, {"rule_type": {"$ne": "legacy"}, "is_seed": {"$ne": True}}, limit=1000)
    return rules


@router.get("/groups/real")
async def get_real_groups():
    groups = await _list_col(GROUPS, {"is_seed": {"$ne": True}}, limit=1000)
    return groups


@router.get("/reviews/real")
async def get_real_reviews():
    reviews = await _list_col(REVIEWS, {"is_seed": {"$ne": True}}, limit=1000)
    return reviews


# ---- Groups (CRUD via /api/reference/groups) ----


def _to_frontend_group(g: dict) -> dict:
    """Map internal group schema to the FirewallGroup shape the React frontend expects."""
    g.pop("_id", None)
    name = g.get("name", "")
    parts = name.replace("grp-", "").replace("g-", "").split("-") if name else []
    return {
        "name": name,
        "app_id": g.get("app_id") or g.get("app_distributed_id", ""),
        "app_distributed_id": g.get("app_distributed_id", ""),
        "nh": g.get("nh") or g.get("nh_id", ""),
        "sz": g.get("sz") or g.get("sz_code", ""),
        "subtype": g.get("subtype") or g.get("group_type", "firewall"),
        "description": g.get("description", ""),
        "members": g.get("members", []),
        "direction": g.get("direction", "egress"),
        "created_at": g.get("created_at", ""),
        "updated_at": g.get("updated_at", ""),
        "group_type": g.get("group_type", "firewall"),
        "dc_id": g.get("dc_id", ""),
        "environment": g.get("environment", ""),
        "vip_entries": g.get("vip_entries", []),
        "endpoint_entries": g.get("endpoint_entries", []),
    }


@router.get("/groups")
async def list_groups_ref(
    app_id: Optional[str] = Query(None),
    dc_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    group_type: Optional[str] = Query(None),
):
    query: dict = {}
    if group_type:
        query["group_type"] = group_type
    if app_id:
        query["$or"] = [{"app_distributed_id": app_id}, {"app_id": app_id}]
    if dc_id:
        query["dc_id"] = dc_id
    if environment:
        query["environment"] = environment
    results = await _list_col(GROUPS, query)
    return [_to_frontend_group(g) for g in results]


@router.post("/groups")
async def create_group_ref(data: dict, user: CurrentUser = Depends(get_current_user)):
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
    await col(GROUPS).insert_one(data)
    await record_audit("groups", name, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


@router.get("/groups-by-name/{group_name}/instances")
async def get_group_instances(group_name: str):
    results = await _list_col(GROUPS, {"name": group_name})
    return [_to_frontend_group(g) for g in results]


@router.get("/groups/{group_name}/affected-rules")
async def get_affected_rules(group_name: str):
    rules = await _list_col(COMPILED_RULES, {"$or": [{"source": group_name}, {"destination": group_name}, {"src_group_ref": group_name}, {"dst_group_ref": group_name}]}, limit=500)
    return {"group": group_name, "affected_rules": len(rules), "rules": rules}


@router.post("/groups/{group_name}/submit-policy-changes")
async def submit_group_policy_changes(group_name: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    affected = await _list_col(COMPILED_RULES, {"$or": [{"source": group_name}, {"destination": group_name}]}, limit=500)
    reviews_created = []
    for rule in affected:
        review_id = f"REV-{uuid.uuid4().hex[:8].upper()}"
        mod_id = f"MOD-{uuid.uuid4().hex[:8].upper()}"
        await col(REVIEWS).insert_one({
            "_id": review_id, "review_id": review_id,
            "rule_id": rule.get("rule_id"), "group_name": group_name,
            "change_type": data.get("change_type"), "status": "Pending",
            "created_at": now, "created_by": user.user_id,
        })
        reviews_created.append({"review_id": review_id, "rule_id": rule.get("rule_id"), "mod_id": mod_id})
    return {"group": group_name, "change_type": data.get("change_type"), "affected_rules": len(affected), "reviews_created": reviews_created}


@router.get("/groups/{group_name}/members")
async def get_group_members_ref(group_name: str, dc_id: Optional[str] = Query(None)):
    q: dict = {"name": group_name}
    if dc_id:
        q["dc_id"] = dc_id
    doc = await col(GROUPS).find_one(q)
    if not doc:
        raise HTTPException(status_code=404, detail="Group not found")
    return _to_frontend_group(doc)


@router.post("/groups/{group_name}/members")
async def add_group_member_ref(group_name: str, data: dict, dc_id: Optional[str] = Query(None), user: CurrentUser = Depends(get_current_user)):
    q: dict = {"name": group_name}
    if dc_id:
        q["dc_id"] = dc_id
    doc = await col(GROUPS).find_one(q)
    if not doc:
        raise HTTPException(status_code=404, detail="Group not found")
    members = doc.get("members", [])
    members.append(data)
    await col(GROUPS).update_one(q, {"$set": {"members": members, "updated_at": utc_now(), "updated_by": user.user_id}})
    doc["members"] = members
    doc.pop("_id", None)
    return doc


@router.delete("/groups/{group_name}/members/{member_value}")
async def remove_group_member_ref(group_name: str, member_value: str, dc_id: Optional[str] = Query(None), user: CurrentUser = Depends(get_current_user)):
    q: dict = {"name": group_name}
    if dc_id:
        q["dc_id"] = dc_id
    doc = await col(GROUPS).find_one(q)
    if not doc:
        raise HTTPException(status_code=404, detail="Group not found")
    members = [m for m in doc.get("members", []) if m.get("value") != member_value]
    await col(GROUPS).update_one(q, {"$set": {"members": members, "updated_at": utc_now(), "updated_by": user.user_id}})
    doc["members"] = members
    doc.pop("_id", None)
    return doc


@router.get("/groups/{group_name}")
async def get_group_ref(group_name: str, dc_id: Optional[str] = Query(None)):
    q: dict = {"name": group_name}
    if dc_id:
        q["dc_id"] = dc_id
    doc = await col(GROUPS).find_one(q)
    if not doc:
        raise HTTPException(status_code=404, detail="Group not found")
    return _to_frontend_group(doc)


@router.put("/groups/{group_name}")
async def update_group_ref(group_name: str, data: dict, dc_id: Optional[str] = Query(None), user: CurrentUser = Depends(get_current_user)):
    q: dict = {"name": group_name}
    if dc_id:
        q["dc_id"] = dc_id
    before = await col(GROUPS).find_one(q)
    if not before:
        raise HTTPException(status_code=404, detail="Group not found")
    data["updated_at"] = utc_now()
    data["updated_by"] = user.user_id
    data.pop("_id", None)
    data.pop("name", None)
    await col(GROUPS).update_one(q, {"$set": data})
    return {"name": group_name, **data}


@router.delete("/groups/{group_name}")
async def delete_group_ref(group_name: str, dc_id: Optional[str] = Query(None), user: CurrentUser = Depends(get_current_user)):
    q: dict = {"name": group_name}
    if dc_id:
        q["dc_id"] = dc_id
    before = await col(GROUPS).find_one(q)
    if not before:
        raise HTTPException(status_code=404, detail="Group not found")
    await col(GROUPS).delete_one(q)
    return {"message": f"Group {group_name} deleted"}


# ---- Firewall Devices ----

@router.get("/firewall-devices")
async def list_firewall_devices():
    return await _list_col(REFERENCE_DATA, {"ref_type": "firewall_device"})


@router.get("/firewall-devices/{device_id}")
async def get_firewall_device(device_id: str):
    doc = await col(REFERENCE_DATA).find_one({"ref_type": "firewall_device", "device_id": device_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Firewall device not found")
    doc.pop("_id", None)
    return doc


@router.post("/firewall-devices")
async def create_firewall_device(data: dict, user: CurrentUser = Depends(get_current_user)):
    data["ref_type"] = "firewall_device"
    result = await col(REFERENCE_DATA).insert_one(data)
    await record_audit("firewall_devices", str(result.inserted_id), "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


@router.put("/firewall-devices/{device_id}")
async def update_firewall_device(device_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(REFERENCE_DATA).find_one({"ref_type": "firewall_device", "device_id": device_id})
    if not before:
        raise HTTPException(status_code=404, detail="Firewall device not found")
    data.pop("_id", None)
    await col(REFERENCE_DATA).update_one({"ref_type": "firewall_device", "device_id": device_id}, {"$set": data})
    return data


@router.delete("/firewall-devices/{device_id}")
async def delete_firewall_device(device_id: str, user: CurrentUser = Depends(get_current_user)):
    await col(REFERENCE_DATA).delete_one({"ref_type": "firewall_device", "device_id": device_id})
    return {"message": f"Firewall device {device_id} deleted"}


@router.get("/firewall-device-patterns")
async def list_firewall_device_patterns():
    patterns = await _list_col(REFERENCE_DATA, {"ref_type": "device_pattern"})
    dc_vendor_docs = await _list_col(REFERENCE_DATA, {"ref_type": "dc_vendor_map"})
    dc_vendor_map = {}
    for d in dc_vendor_docs:
        dc_vendor_map[d.get("dc_id", "")] = d.get("vendors", {})
    return {"patterns": patterns, "dc_vendor_map": dc_vendor_map}


# ---- Legacy Rules ----

LEGACY_RULES_COLLECTION = "compiled_rules"


def _to_frontend_legacy(r: dict) -> dict:
    """Map internal legacy rule to the LegacyRule shape the React frontend expects."""
    src = r.get("rule_source") or r.get("source", "")
    dst = r.get("rule_destination") or r.get("destination", "")
    svc = r.get("rule_service") or r.get("service", "")
    act = r.get("rule_action") or r.get("action", "permit")
    ms = r.get("migration_status", "Not Started")
    ms_map = {"pending": "Not Started", "in_progress": "In Progress", "mapped": "Mapped", "migrated": "Completed"}
    return {
        "id": r.get("rule_id", ""),
        "rule_id": r.get("rule_id", ""),
        "app_id": r.get("app_id", ""),
        "app_distributed_id": r.get("app_distributed_id", ""),
        "app_name": r.get("app_name") or r.get("rule_name", ""),
        "inventory_item": r.get("inventory_item", ""),
        "policy_name": r.get("policy_name", ""),
        "rule_global": r.get("rule_global", False),
        "rule_action": act,
        "rule_source": src,
        "rule_source_expanded": r.get("rule_source_expanded", src),
        "rule_source_zone": r.get("rule_source_zone") or r.get("source_zone", ""),
        "rule_destination": dst,
        "rule_destination_expanded": r.get("rule_destination_expanded", dst),
        "rule_destination_zone": r.get("rule_destination_zone") or r.get("destination_zone", ""),
        "rule_service": svc,
        "rule_service_expanded": r.get("rule_service_expanded", svc),
        "rn": r.get("rn") or r.get("rule_number", 0),
        "rc": r.get("rc") or r.get("hit_count", 0),
        "is_standard": r.get("is_standard", False),
        "migration_status": ms_map.get(ms, ms),
        "rule_status": r.get("rule_status") or r.get("lifecycle_status", "Deployed"),
        "rule_migration_status": r.get("rule_migration_status", ms_map.get(ms, ms)),
        "environment": r.get("environment", ""),
        "firewall_name": r.get("firewall_name", ""),
        "description": r.get("description", ""),
        "last_hit_date": r.get("last_hit_date"),
        "created_at": r.get("created_at", ""),
        "updated_at": r.get("updated_at", ""),
    }


@router.get("/legacy-rules")
async def list_legacy_rules(
    app_id: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    exclude_migrated: Optional[bool] = Query(False),
    migration_only: Optional[bool] = Query(False),
):
    query: dict = {"rule_type": "legacy"}
    if app_id:
        query["$or"] = [{"app_distributed_id": app_id}, {"app_id": app_id}]
    if environment:
        query["environment"] = environment
    if exclude_migrated:
        query["migration_status"] = {"$ne": "migrated"}
    if migration_only:
        query["migration_status"] = {"$in": ["pending", "in_progress"]}

    cursor = col(LEGACY_RULES_COLLECTION).find(query).sort("rule_number", 1).limit(1000)
    results = await cursor.to_list(length=1000)
    return [_to_frontend_legacy(r) for r in results]


@router.get("/legacy-rules/migrated")
async def get_migrated_rules():
    return await _list_col(LEGACY_RULES_COLLECTION, {"rule_type": "legacy", "migration_status": "migrated"})


@router.get("/legacy-rules/{rule_id}")
async def get_legacy_rule(rule_id: str):
    doc = await col(LEGACY_RULES_COLLECTION).find_one({"rule_id": rule_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Legacy rule not found")
    return _to_frontend_legacy(doc)


@router.put("/legacy-rules/{rule_id}")
async def update_legacy_rule(rule_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(LEGACY_RULES_COLLECTION).find_one({"rule_id": rule_id})
    if not before:
        raise HTTPException(status_code=404, detail="Legacy rule not found")
    data.pop("_id", None)
    data.pop("rule_id", None)
    data["updated_at"] = utc_now()
    data["updated_by"] = user.user_id
    await col(LEGACY_RULES_COLLECTION).update_one({"rule_id": rule_id}, {"$set": data})
    after = await col(LEGACY_RULES_COLLECTION).find_one({"rule_id": rule_id})
    await record_audit("legacy_rules", rule_id, "update", user.user_id, user.user_email, user.user_team, before_snapshot=_s(before), after_snapshot=_s(after))
    if after:
        after.pop("_id", None)
    return after


@router.delete("/legacy-rules/{rule_id}")
async def delete_legacy_rule(rule_id: str, user: CurrentUser = Depends(get_current_user)):
    before = await col(LEGACY_RULES_COLLECTION).find_one({"rule_id": rule_id})
    if not before:
        raise HTTPException(status_code=404, detail="Legacy rule not found")
    await col(LEGACY_RULES_COLLECTION).delete_one({"rule_id": rule_id})
    await record_audit("legacy_rules", rule_id, "delete", user.user_id, user.user_email, user.user_team, before_snapshot=_s(before))
    return {"message": f"Legacy rule {rule_id} deleted"}


@router.delete("/legacy-rules/clear-all")
async def clear_all_legacy_rules(user: CurrentUser = Depends(get_current_user)):
    result = await col(LEGACY_RULES_COLLECTION).delete_many({"rule_type": "legacy"})
    return {"message": "All legacy rules cleared", "deleted": result.deleted_count}


@router.post("/legacy-rules/bulk-update-app-id")
async def bulk_update_legacy_rule_app_id(data: dict, user: CurrentUser = Depends(get_current_user)):
    rule_ids = data.get("rule_ids", [])
    app_distributed_id = data.get("app_distributed_id", "")
    app_name = data.get("app_name", "")
    extra_fields = data.get("extra_fields", {})
    update_doc: dict = {"app_distributed_id": app_distributed_id, "updated_at": utc_now(), "updated_by": user.user_id}
    if app_name:
        update_doc["app_name"] = app_name
    update_doc.update(extra_fields)

    app_found = False
    app = await col(APPLICATIONS).find_one({"app_distributed_id": app_distributed_id})
    if app:
        app_found = True
        update_doc.setdefault("app_name", app.get("name", ""))

    count = 0
    for rid in rule_ids:
        result = await col(LEGACY_RULES_COLLECTION).update_one({"rule_id": rid}, {"$set": update_doc})
        count += result.modified_count
    return {"updated": count, "app_distributed_id": app_distributed_id, "app_found": app_found, "fields_copied": list(update_doc.keys())}


@router.post("/legacy-rules/migrate")
async def migrate_legacy_rules(data: dict, user: CurrentUser = Depends(get_current_user)):
    rule_ids = data.get("rule_ids", [])
    now = utc_now()
    migrated = 0
    rules = []
    for rid in rule_ids:
        result = await col(LEGACY_RULES_COLLECTION).update_one({"rule_id": rid}, {"$set": {"migration_status": "migrated", "migrated_at": now, "migrated_by": user.user_id}})
        if result.modified_count > 0:
            migrated += 1
            doc = await col(LEGACY_RULES_COLLECTION).find_one({"rule_id": rid})
            if doc:
                doc.pop("_id", None)
                rules.append(doc)
    return {"migrated": migrated, "rules": rules}


@router.post("/legacy-rules/submit-for-review")
async def submit_legacy_rules_for_review(data: dict, user: CurrentUser = Depends(get_current_user)):
    rule_ids = data.get("rule_ids", [])
    comments = data.get("comments", "")
    now = utc_now()
    reviews = []
    for rid in rule_ids:
        review_id = f"REV-{uuid.uuid4().hex[:8].upper()}"
        review = {
            "_id": review_id, "review_id": review_id,
            "rule_id": rid, "status": "Pending", "comments": comments,
            "created_at": now, "created_by": user.user_id,
        }
        await col(REVIEWS).insert_one(review)
        review.pop("_id", None)
        reviews.append(review)
    return {"submitted": len(reviews), "reviews": reviews}


@router.post("/legacy-rules/{rule_id}/compile")
async def compile_legacy_rule(rule_id: str, vendor: str = Query("generic")):
    rule = await col(LEGACY_RULES_COLLECTION).find_one({"rule_id": rule_id})
    if not rule:
        raise HTTPException(status_code=404, detail="Legacy rule not found")
    rule.pop("_id", None)
    src = rule.get("source", "")
    dst = rule.get("destination", "")
    port = rule.get("service", rule.get("port", ""))
    action = rule.get("action", "permit")
    config = f"# Legacy Rule {rule_id}\npermit {src} -> {dst} port {port} action {action}"
    return {"rule_id": rule_id, "vendor": vendor, "config": config, "rule": rule}


@router.post("/legacy-rules/{rule_id}/modify")
async def modify_legacy_rule(rule_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    modifications = data.get("modifications", {})
    comments = data.get("comments", "")
    before = await col(LEGACY_RULES_COLLECTION).find_one({"rule_id": rule_id})
    if not before:
        raise HTTPException(status_code=404, detail="Legacy rule not found")
    if modifications:
        await col(LEGACY_RULES_COLLECTION).update_one({"rule_id": rule_id}, {"$set": {**modifications, "updated_at": now}})
    mod_id = f"MOD-{uuid.uuid4().hex[:8].upper()}"
    return {"mod_id": mod_id, "rule_id": rule_id, "modifications": modifications, "comments": comments, "status": "Applied", "created_at": now}


@router.get("/legacy-rules/{rule_id}/ngdc-recommendations")
async def get_ngdc_recommendations(rule_id: str):
    rule = await col(LEGACY_RULES_COLLECTION).find_one({"rule_id": rule_id})
    if not rule:
        raise HTTPException(status_code=404, detail="Legacy rule not found")
    app_id = rule.get("app_distributed_id", "")
    return {
        "rule_id": rule_id,
        "recommendations": [
            {"field": "source", "current": rule.get("source", ""), "suggested": f"grp-{app_id}-SRC-NH02-GEN" if app_id else ""},
            {"field": "destination", "current": rule.get("destination", ""), "suggested": f"grp-{app_id}-DST-NH02-GEN" if app_id else ""},
        ],
        "confidence": "low",
    }


# ---- Studio Rule Modifications ----

@router.post("/rules/{rule_id}/modify")
async def modify_studio_rule(rule_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    now = utc_now()
    modifications = data.get("modifications", {})
    delta = data.get("delta", {})
    comments = data.get("comments", "")
    before = await col(COMPILED_RULES).find_one({"rule_id": rule_id})
    if not before:
        raise HTTPException(status_code=404, detail="Rule not found")
    if modifications:
        await col(COMPILED_RULES).update_one({"rule_id": rule_id}, {"$set": {**modifications, "updated_at": now}})
    mod_id = f"MOD-{uuid.uuid4().hex[:8].upper()}"
    return {"mod_id": mod_id, "rule_id": rule_id, "modifications": modifications, "delta": delta, "comments": comments, "status": "Applied", "created_at": now}


@router.get("/rule-modifications")
async def list_rule_modifications(rule_id: Optional[str] = Query(None)):
    query: dict = {"ref_type": "rule_modification"}
    if rule_id:
        query["rule_id"] = rule_id
    return await _list_col(REFERENCE_DATA, query)


@router.post("/rule-modifications/{mod_id}/approve")
async def approve_rule_modification(mod_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    return {"mod_id": mod_id, "status": "Approved", "approved_at": utc_now(), "approved_by": user.user_id}


@router.post("/rule-modifications/{mod_id}/reject")
async def reject_rule_modification(mod_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    return {"mod_id": mod_id, "status": "Rejected", "rejected_at": utc_now(), "rejected_by": user.user_id, "notes": data.get("notes", "")}


# ---- NGDC Mappings ----

@router.get("/ngdc-mappings")
async def list_ngdc_mappings():
    return await _list_col(REFERENCE_DATA, {"ref_type": "ngdc_mapping"})


@router.post("/ngdc-mappings")
async def create_ngdc_mapping(data: dict, user: CurrentUser = Depends(get_current_user)):
    data["ref_type"] = "ngdc_mapping"
    await col(REFERENCE_DATA).insert_one(data)
    data.pop("_id", None)
    return data


@router.put("/ngdc-mappings/{mapping_id}")
async def update_ngdc_mapping(mapping_id: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(REFERENCE_DATA).find_one({"_id": mapping_id, "ref_type": "ngdc_mapping"})
    if not before:
        raise HTTPException(status_code=404, detail="NGDC mapping not found")
    data.pop("_id", None)
    await col(REFERENCE_DATA).update_one({"_id": mapping_id}, {"$set": data})
    return data


@router.delete("/ngdc-mappings/{mapping_id}")
async def delete_ngdc_mapping(mapping_id: str, user: CurrentUser = Depends(get_current_user)):
    await col(REFERENCE_DATA).delete_one({"_id": mapping_id, "ref_type": "ngdc_mapping"})
    return {"message": f"NGDC mapping {mapping_id} deleted"}


@router.post("/ngdc-mappings/bulk")
async def bulk_ngdc_mappings(data: dict, user: CurrentUser = Depends(get_current_user)):
    mappings = data.get("mappings", [])
    for m in mappings:
        m["ref_type"] = "ngdc_mapping"
    if mappings:
        await col(REFERENCE_DATA).insert_many(mappings)
    return {"created": len(mappings)}


# ---- Birthright ----

@router.post("/birthright/validate")
async def validate_birthright(data: dict):
    return {"valid": True, "result": "permitted", "reason": "Birthright validation passed", "details": []}


@router.get("/birthright/matrix")
async def get_birthright_matrix():
    return await _list_col(REFERENCE_DATA, {"ref_type": "birthright_matrix"})


@router.put("/birthright/matrix/{matrix_type}")
async def update_birthright_matrix(matrix_type: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    entries = data.get("entries", [])
    await col(REFERENCE_DATA).delete_many({"ref_type": "birthright_matrix", "matrix_type": matrix_type})
    for entry in entries:
        entry["ref_type"] = "birthright_matrix"
        entry["matrix_type"] = matrix_type
        await col(REFERENCE_DATA).insert_one(entry)
    return entries


@router.post("/birthright/matrix/{matrix_type}")
async def add_birthright_entry(matrix_type: str, data: dict, user: CurrentUser = Depends(get_current_user)):
    data["ref_type"] = "birthright_matrix"
    data["matrix_type"] = matrix_type
    await col(REFERENCE_DATA).insert_one(data)
    data.pop("_id", None)
    return data


# ---- IP Classification ----

@router.post("/classify-ip")
async def classify_ip(data: dict):
    ip = data.get("ip", "")
    return {"ip": ip, "classification": "internal", "zone": "GEN", "zone_name": "General", "neighbourhood": "NH02"}


@router.post("/classify-ips")
async def classify_ips(data: dict):
    ips = data.get("ips", [])
    return [{"ip": ip, "classification": "internal", "zone": "GEN"} for ip in ips]


@router.post("/classify-rule-endpoints")
async def classify_rule_endpoints(data: dict):
    return {"source": {"classification": "internal", "zone": "GEN"}, "destination": {"classification": "internal", "zone": "GEN"}}


@router.post("/compile-hybrid-rule")
async def compile_hybrid_rule(data: dict):
    return {"compiled": True, "config": "# Hybrid rule compiled", "warnings": []}


@router.post("/determine-cross-dc-boundaries")
async def determine_cross_dc_boundaries(data: dict):
    return {"cross_dc": False, "boundaries": [], "dc_pairs": []}


# ---- IP Mappings ----

@router.get("/ip-mappings")
async def list_ip_mappings():
    return await _list_col(REFERENCE_DATA, {"ref_type": "ip_mapping"})


@router.post("/ip-mappings/import")
async def import_ip_mappings(data: dict, user: CurrentUser = Depends(get_current_user)):
    mappings = data.get("mappings", [])
    for m in mappings:
        m["ref_type"] = "ip_mapping"
    if mappings:
        await col(REFERENCE_DATA).insert_many(mappings)
    return {"imported": len(mappings)}


# ---- Migration Data ----

@router.get("/logical-flow-rules")
async def list_logical_flow_rules():
    return await _list_col(REFERENCE_DATA, {"ref_type": "logical_flow_rule"})


@router.get("/migration-groups")
async def list_migration_groups():
    return await _list_col(GROUPS, {"is_migration": True})


@router.get("/migration-history")
async def list_migration_history():
    return await _list_col(AUDIT_TRAIL, {"operation": {"$in": ["migrate", "migration"]}})


# ---- User Data (summary endpoints) ----

@router.get("/user-data/summary")
async def user_data_summary():
    rules = await col(COMPILED_RULES).count_documents({"rule_type": {"$ne": "legacy"}})
    legacy = await col(COMPILED_RULES).count_documents({"rule_type": "legacy"})
    groups = await col(GROUPS).count_documents({})
    requests = await col(REQUESTS).count_documents({})
    reviews = await col(REVIEWS).count_documents({})
    return {"rules": rules, "legacy_rules": legacy, "groups": groups, "requests": requests, "reviews": reviews}


@router.get("/user-data/summary/by-app")
async def user_data_summary_by_app():
    apps = await _list_col(APPLICATIONS, {})
    result = []
    for app in apps:
        aid = app.get("app_distributed_id", "")
        rules = await col(COMPILED_RULES).count_documents({"app_distributed_id": aid})
        groups = await col(GROUPS).count_documents({"app_distributed_id": aid})
        result.append({"app_distributed_id": aid, "name": app.get("name", ""), "rules": rules, "groups": groups})
    return result


@router.get("/user-data/summary/by-env")
async def user_data_summary_by_env():
    envs = ["Production", "Non-Production", "Pre-Production"]
    result = []
    for env in envs:
        rules = await col(COMPILED_RULES).count_documents({"environment": env})
        groups = await col(GROUPS).count_documents({"environment": env})
        result.append({"environment": env, "rules": rules, "groups": groups})
    return result


@router.get("/user-data/all")
async def user_data_all():
    return {"rules": [], "groups": [], "legacy_rules": [], "reviews": [], "modifications": []}


@router.get("/user-data/studio-rules")
async def user_data_studio_rules():
    return await _list_col(COMPILED_RULES, {"rule_type": {"$ne": "legacy"}, "is_seed": {"$ne": True}})


@router.get("/user-data/firewall-rules")
async def user_data_firewall_rules():
    return await _list_col(COMPILED_RULES, {"is_seed": {"$ne": True}})


@router.get("/user-data/legacy-rules")
async def user_data_legacy_rules():
    return await _list_col(COMPILED_RULES, {"rule_type": "legacy", "is_seed": {"$ne": True}})


@router.get("/user-data/groups")
async def user_data_groups():
    return await _list_col(GROUPS, {"is_seed": {"$ne": True}})


@router.get("/user-data/reviews")
async def user_data_reviews():
    return await _list_col(REVIEWS, {"is_seed": {"$ne": True}})


@router.get("/user-data/modifications")
async def user_data_modifications():
    return await _list_col(REFERENCE_DATA, {"ref_type": "rule_modification", "is_seed": {"$ne": True}})


@router.get("/user-data/migration")
async def user_data_migration():
    return await _list_col(MIGRATIONS, {"is_seed": {"$ne": True}})
