"""Admin routes — data store management, upload, and switching.

Key endpoints:
  GET  /api/admin/store/status       — current store mode + collection counts
  POST /api/admin/store/switch       — switch between json and mongodb
  POST /api/admin/store/upload-to-mongo — load JSON files into MongoDB
  POST /api/admin/store/reload       — reload JSON files from disk
  POST /api/admin/store/upload-json  — upload a JSON file for a collection
"""

import json

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from app.config import settings
from app.db.store import get_store, reset_store, JsonFileStore, MongoStore, COLLECTION_FILES

router = APIRouter(prefix="/api/admin", tags=["Admin"])


@router.get("/store/status")
async def store_status():
    """Get current data store mode and collection document counts."""
    store = get_store()
    mode = "json" if isinstance(store, JsonFileStore) else "mongodb"
    counts: dict[str, int] = {}
    for coll_name in COLLECTION_FILES:
        counts[coll_name] = await store.count(coll_name)
    return {
        "mode": mode,
        "data_dir": settings.json_data_dir if mode == "json" else None,
        "mongodb_uri": settings.mongodb_uri if mode == "mongodb" else None,
        "mongodb_database": settings.mongodb_database if mode == "mongodb" else None,
        "collections": counts,
        "total_documents": sum(counts.values()),
    }


@router.post("/store/switch")
async def switch_store(mode: str = Form(...)):
    """Switch data store mode at runtime. Does NOT persist across restarts.

    To persist, set DATA_STORE env var in .env file.
    """
    if mode not in ("json", "mongodb"):
        raise HTTPException(400, "Mode must be 'json' or 'mongodb'")

    settings.data_store = mode
    reset_store()

    store = get_store()
    return {
        "switched_to": mode,
        "store_type": type(store).__name__,
        "message": f"Runtime switch to {mode}. Set DATA_STORE={mode} in .env to persist.",
    }


@router.post("/store/reload")
async def reload_json_store():
    """Reload all collections from JSON files on disk (json mode only)."""
    store = get_store()
    if not isinstance(store, JsonFileStore):
        raise HTTPException(400, "Reload only works in json mode. Current mode: mongodb")

    counts = await store.load_from_files()
    return {
        "reloaded": True,
        "collections": counts,
        "total_documents": sum(counts.values()),
    }


@router.post("/store/upload-to-mongo")
async def upload_json_to_mongo():
    """Load all JSON files from data/ directory into MongoDB.

    Reads each JSON file, clears the corresponding MongoDB collection,
    and inserts all documents. Use this to migrate from json → mongodb.
    """
    if settings.data_store == "json":
        # Temporarily create a MongoDB store for the upload
        mongo_store = MongoStore()
    else:
        mongo_store = get_store()
        if not isinstance(mongo_store, MongoStore):
            raise HTTPException(400, "Expected MongoDB store")

    # Load from JSON files
    json_store = JsonFileStore(data_dir=settings.json_data_dir)
    await json_store.load_from_files()

    results: dict[str, dict] = {}
    for coll_name in COLLECTION_FILES:
        docs = await json_store.find(coll_name, limit=10000)
        if docs:
            # Clear existing
            await mongo_store.delete_many(coll_name, {})
            # Insert
            ids = await mongo_store.insert_many(coll_name, docs)
            results[coll_name] = {"uploaded": len(ids)}
        else:
            results[coll_name] = {"uploaded": 0}

    return {
        "success": True,
        "message": "JSON data loaded into MongoDB",
        "collections": results,
    }


@router.post("/store/upload-json/{collection}")
async def upload_json_file(
    collection: str,
    file: UploadFile = File(...),
    merge: bool = Form(False),
):
    """Upload a JSON file to replace or merge with a collection's data.

    Args:
        collection: Target collection name (e.g., 'groups', 'applications')
        file: JSON file (.json) containing an array of documents
        merge: If True, add to existing data. If False, replace all.
    """
    if collection not in COLLECTION_FILES:
        raise HTTPException(
            400,
            f"Unknown collection '{collection}'. Valid: {list(COLLECTION_FILES.keys())}",
        )

    content = await file.read()
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid JSON: {e}")

    if not isinstance(data, list):
        raise HTTPException(400, "JSON must be an array of documents")

    store = get_store()

    if not merge:
        await store.delete_many(collection, {})

    inserted = 0
    for doc in data:
        await store.insert_one(collection, doc)
        inserted += 1

    return {
        "collection": collection,
        "mode": "merge" if merge else "replace",
        "documents_uploaded": inserted,
        "total_in_collection": await store.count(collection),
    }


@router.get("/store/export-json/{collection}")
async def export_collection_json(collection: str):
    """Export a collection's data as JSON (for backup or migration)."""
    if collection not in COLLECTION_FILES:
        raise HTTPException(
            400,
            f"Unknown collection '{collection}'. Valid: {list(COLLECTION_FILES.keys())}",
        )

    store = get_store()
    docs = await store.find(collection, limit=10000)
    return docs


@router.get("/store/collections")
async def list_collections():
    """List all available collections and their JSON file mappings."""
    return {
        "collections": list(COLLECTION_FILES.keys()),
        "file_mappings": COLLECTION_FILES,
        "current_mode": settings.data_store,
    }
