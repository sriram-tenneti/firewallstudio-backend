"""Reference data CRUD endpoints — NHs, SZs, DCs, Apps, Policy Matrix, etc."""

from fastapi import APIRouter, Depends, HTTPException, Query
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


# ---- Applications ----

@router.get("/applications")
async def list_applications(
    team: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
):
    query: dict = {}
    if team:
        query["owner_team"] = team
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


# ---- Shared Service Presences ----

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
    return await _list_col(NEIGHBOURHOODS, {})


@router.post("/neighbourhoods")
async def create_neighbourhood(data: dict, user: CurrentUser = Depends(get_current_user)):
    nh_id = data.get("nh_id", "")
    data["_id"] = nh_id
    await col(NEIGHBOURHOODS).insert_one(data)
    await record_audit("neighbourhoods", nh_id, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


# ---- Security Zones ----

@router.get("/security-zones")
async def list_security_zones():
    return await _list_col(SECURITY_ZONES, {})


@router.post("/security-zones")
async def create_security_zone(data: dict, user: CurrentUser = Depends(get_current_user)):
    code = data.get("code", "")
    data["_id"] = code
    await col(SECURITY_ZONES).insert_one(data)
    await record_audit("security_zones", code, "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


# ---- Data Centers ----

@router.get("/datacenters/ngdc")
async def list_ngdc_datacenters():
    return await _list_col(NGDC_DATACENTERS, {})


@router.get("/datacenters/legacy")
async def list_legacy_datacenters():
    return await _list_col(LEGACY_DATACENTERS, {})


# ---- Environments ----

@router.get("/environments")
async def list_environments():
    return await _list_col(ENVIRONMENTS, {})


# ---- Policy Matrix ----

@router.get("/policy-matrix")
async def list_policy_matrix():
    return await _list_col(POLICY_MATRIX, {}, limit=1000)


@router.post("/policy-matrix")
async def create_policy_entry(data: dict, user: CurrentUser = Depends(get_current_user)):
    result = await col(POLICY_MATRIX).insert_one(data)
    await record_audit("policy_matrix", str(result.inserted_id), "create", user.user_id, user.user_email, user.user_team, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


# ---- Naming Standards ----

@router.get("/naming-standards")
async def get_naming_standards():
    doc = await col(NAMING_STANDARDS).find_one({})
    if doc:
        doc.pop("_id", None)
    return doc or {}


# ---- Port Catalog ----

@router.get("/port-catalog")
async def list_port_catalog():
    return await _list_col(PORT_CATALOG, {})


# ---- Org Config ----

@router.get("/org-config")
async def get_org_config():
    doc = await col(ORG_CONFIG).find_one({})
    if doc:
        doc.pop("_id", None)
    return doc or {}


@router.put("/org-config")
async def update_org_config(data: dict, user: CurrentUser = Depends(get_current_user)):
    before = await col(ORG_CONFIG).find_one({})
    if before:
        data.pop("_id", None)
        await col(ORG_CONFIG).replace_one({"_id": before["_id"]}, data)
    else:
        await col(ORG_CONFIG).insert_one(data)
    await record_audit("org_config", "org_config", "update", user.user_id, user.user_email, user.user_team, before_snapshot=_s(before) if before else None, after_snapshot=_s(data))
    data.pop("_id", None)
    return data


# ---- App DC Mappings ----

@router.get("/app-dc-mappings")
async def list_app_dc_mappings(app_distributed_id: Optional[str] = Query(None)):
    query: dict = {}
    if app_distributed_id:
        query["app_distributed_id"] = app_distributed_id
    return await _list_col(APP_DC_MAPPINGS, query)


def _s(doc: dict | None) -> dict | None:
    if doc is None:
        return None
    d = dict(doc)
    d.pop("_id", None)
    return d
