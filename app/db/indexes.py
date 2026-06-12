"""Index definitions applied on startup.

Ensures all required indexes exist for query performance.
"""

from motor.motor_asyncio import AsyncIOMotorDatabase
import pymongo


async def ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    """Create all required indexes (idempotent)."""

    # applications — _id is app_distributed_id (natural key)
    await db.applications.create_index("owner_team")
    await db.applications.create_index("deployment_mode")

    # app_presences
    await db.app_presences.create_index([
        ("app_distributed_id", pymongo.ASCENDING),
        ("dc_id", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
    ])

    # shared_services
    await db.shared_services.create_index("owner_team")

    # shared_service_presences
    await db.shared_service_presences.create_index([
        ("service_id", pymongo.ASCENDING),
        ("dc_id", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
    ])

    # firewall_groups
    await db.firewall_groups.create_index("app_distributed_id")
    await db.firewall_groups.create_index([
        ("dc_id", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
        ("direction", pymongo.ASCENDING),
    ])

    # ingress_groups
    await db.ingress_groups.create_index("app_distributed_id")
    await db.ingress_groups.create_index([
        ("dc_id", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
    ])

    # rule_requests
    await db.rule_requests.create_index([
        ("app_distributed_id", pymongo.ASCENDING),
        ("status", pymongo.ASCENDING),
    ])
    await db.rule_requests.create_index([
        ("environment", pymongo.ASCENDING),
        ("status", pymongo.ASCENDING),
        ("created_at", pymongo.DESCENDING),
    ])

    # physical_rules
    await db.physical_rules.create_index("request_id")
    await db.physical_rules.create_index([
        ("app_distributed_id", pymongo.ASCENDING),
        ("environment", pymongo.ASCENDING),
    ])

    # request_status_history
    await db.request_status_history.create_index([
        ("app_distributed_id", pymongo.ASCENDING),
        ("transitioned_at", pymongo.DESCENDING),
    ])
    await db.request_status_history.create_index([
        ("request_id", pymongo.ASCENDING),
        ("transitioned_at", pymongo.ASCENDING),
    ])
    await db.request_status_history.create_index([
        ("request_type", pymongo.ASCENDING),
        ("to_status", pymongo.ASCENDING),
        ("transitioned_at", pymongo.DESCENDING),
    ])

    # audit_trail
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

    # group_change_requests
    await db.group_change_requests.create_index([
        ("app_distributed_id", pymongo.ASCENDING),
        ("status", pymongo.ASCENDING),
    ])

    # reviews
    await db.reviews.create_index([
        ("status", pymongo.ASCENDING),
        ("submitted_at", pymongo.DESCENDING),
    ])
    await db.reviews.create_index([
        ("module", pymongo.ASCENDING),
        ("status", pymongo.ASCENDING),
    ])

    # lifecycle_events
    await db.lifecycle_events.create_index([
        ("rule_id", pymongo.ASCENDING),
        ("timestamp", pymongo.DESCENDING),
    ])
    await db.lifecycle_events.create_index([
        ("event_type", pymongo.ASCENDING),
        ("timestamp", pymongo.DESCENDING),
    ])

    # migrations
    await db.migrations.create_index("application")
    await db.migration_mappings.create_index("migration_id")
    await db.migration_rule_lifecycle.create_index("migration_id")

    # chg_requests
    await db.chg_requests.create_index("status")

    # policy_matrix
    await db.policy_matrix.create_index([
        ("source_zone", pymongo.ASCENDING),
        ("dest_zone", pymongo.ASCENDING),
    ])
