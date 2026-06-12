"""Index definitions for the 10 consolidated collections.

Applied on startup when DATA_STORE=mongodb.
"""

from motor.motor_asyncio import AsyncIOMotorDatabase
import pymongo


async def ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    """Create all required indexes (idempotent)."""

    # ---- applications ----
    await db.applications.create_index("owner_team")
    await db.applications.create_index("environment")
    await db.applications.create_index("presences.dc_id")

    # ---- groups (firewall + ingress, discriminated by group_type) ----
    await db.groups.create_index("app_distributed_id")
    await db.groups.create_index("group_type")
    await db.groups.create_index([
        ("dc_id", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
        ("group_type", pymongo.ASCENDING),
    ])
    await db.groups.create_index([
        ("name", pymongo.ASCENDING),
        ("dc_id", pymongo.ASCENDING),
    ], unique=True)

    # ---- requests (rule + group_change, discriminated by request_type) ----
    await db.requests.create_index("request_type")
    await db.requests.create_index([
        ("app_distributed_id", pymongo.ASCENDING),
        ("status", pymongo.ASCENDING),
    ])
    await db.requests.create_index([
        ("request_type", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
        ("status", pymongo.ASCENDING),
        ("created_at", pymongo.DESCENDING),
    ])

    # ---- compiled_rules ----
    await db.compiled_rules.create_index("request_id")
    await db.compiled_rules.create_index([
        ("app_distributed_id", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
    ])

    # ---- reference_data (type-discriminated) ----
    await db.reference_data.create_index("ref_type")
    await db.reference_data.create_index([
        ("ref_type", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
    ])

    # ---- request_status_history (append-only) ----
    await db.request_status_history.create_index([
        ("app_distributed_id", pymongo.ASCENDING),
        ("transitioned_at", pymongo.DESCENDING),
    ])
    await db.request_status_history.create_index([
        ("request_id", pymongo.ASCENDING),
        ("transitioned_at", pymongo.ASCENDING),
    ])

    # ---- audit_trail ----
    await db.audit_trail.create_index([
        ("app_distributed_id", pymongo.ASCENDING),
        ("timestamp", pymongo.DESCENDING),
    ])
    await db.audit_trail.create_index([
        ("collection", pymongo.ASCENDING),
        ("document_id", pymongo.ASCENDING),
        ("timestamp", pymongo.DESCENDING),
    ])
    await db.audit_trail.create_index([
        ("user_id", pymongo.ASCENDING),
        ("timestamp", pymongo.DESCENDING),
    ])

    # ---- reviews ----
    await db.reviews.create_index("request_id")
    await db.reviews.create_index([
        ("decision", pymongo.ASCENDING),
        ("reviewed_at", pymongo.DESCENDING),
    ])

    # ---- migrations ----
    await db.migrations.create_index("app_distributed_id")

    # ---- shared_services (type-discriminated) ----
    await db.shared_services.create_index("service_type")
