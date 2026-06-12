"""Seed data loading endpoint — populates MongoDB from JSON files."""

import json
from pathlib import Path

from fastapi import APIRouter

from app.db.collections import (
    col,
    NEIGHBOURHOODS, SECURITY_ZONES, NGDC_DATACENTERS,
    APPLICATIONS, POLICY_MATRIX, APP_DC_MAPPINGS,
)

router = APIRouter(prefix="/api/seed", tags=["Seed Data"])

SEED_DIR = Path(__file__).parent.parent.parent / "seed-json"


@router.post("/load")
async def load_seed_data():
    """Load seed data from JSON files into MongoDB.

    Idempotent — skips collections that already have data.
    """
    loaded: list[str] = []

    mappings = [
        ("neighbourhoods.json", NEIGHBOURHOODS, "nh_id"),
        ("security_zones.json", SECURITY_ZONES, "code"),
        ("datacenters.json", NGDC_DATACENTERS, "code"),
        ("applications.json", APPLICATIONS, "app_distributed_id"),
        ("policy_matrix.json", POLICY_MATRIX, None),
        ("app_dc_mappings.json", APP_DC_MAPPINGS, None),
    ]

    for filename, collection_name, id_field in mappings:
        filepath = SEED_DIR / filename
        if not filepath.exists():
            continue

        count = await col(collection_name).count_documents({})
        if count > 0:
            continue

        with open(filepath) as f:
            data = json.load(f)

        if isinstance(data, list):
            for item in data:
                if id_field and id_field in item:
                    item["_id"] = item[id_field]
            if data:
                await col(collection_name).insert_many(data)
        elif isinstance(data, dict):
            # Some files are key-value dicts
            docs = []
            for key, val in data.items():
                if isinstance(val, dict):
                    val["_id"] = key
                    docs.append(val)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict) and id_field and id_field in item:
                            item["_id"] = item[id_field]
                    docs.extend(val)
            if docs:
                await col(collection_name).insert_many(docs)

        loaded.append(filename)

    return {"loaded": loaded, "message": f"Seeded {len(loaded)} collections"}
