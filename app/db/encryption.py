"""MongoDB Client-Side Field Level Encryption (CSFLE) setup.

Configures automatic encryption for sensitive fields across collections.
In development mode (encryption_enabled=False), no encryption is applied.
"""

import base64
import os

from app.config import settings

# Fields that should be encrypted per collection.
# Format: collection_name -> list of field paths + bsonType
ENCRYPTED_FIELD_SPECS: dict[str, list[dict]] = {
    "firewall_groups": [
        {"path": "members.value", "bsonType": "string"},
    ],
    "ingress_groups": [
        {"path": "members.value", "bsonType": "string"},
        {"path": "vip_entries.vip_address", "bsonType": "string"},
        {"path": "endpoint_entries.endpoint_name", "bsonType": "string"},
    ],
    "audit_trail": [
        {"path": "user_email", "bsonType": "string"},
        {"path": "before_snapshot", "bsonType": "object"},
        {"path": "after_snapshot", "bsonType": "object"},
    ],
    "rule_requests": [
        {"path": "owner", "bsonType": "string"},
    ],
    "physical_rules": [
        {"path": "compiled_text", "bsonType": "string"},
    ],
    "itsm_connectors": [
        {"path": "auth_config", "bsonType": "object"},
    ],
}


def get_kms_providers() -> dict:
    """Build KMS provider config based on settings."""
    if settings.kms_provider == "local":
        key = settings.local_master_key
        if not key:
            key = base64.b64encode(os.urandom(96)).decode()
        return {"local": {"key": base64.b64decode(key)}}

    if settings.kms_provider == "aws":
        return {
            "aws": {
                "accessKeyId": settings.aws_access_key_id,
                "secretAccessKey": settings.aws_secret_access_key,
            }
        }

    return {"local": {"key": os.urandom(96)}}


def get_encryption_schema_map() -> dict:
    """Build the JSON schema map for automatic encryption.

    Returns empty dict when encryption is disabled.
    """
    if not settings.encryption_enabled:
        return {}

    db_ns = settings.mongodb_database
    schema_map: dict = {}

    for coll_name, fields in ENCRYPTED_FIELD_SPECS.items():
        namespace = f"{db_ns}.{coll_name}"
        properties: dict = {}
        for field_spec in fields:
            properties[field_spec["path"]] = {
                "encrypt": {
                    "bsonType": field_spec["bsonType"],
                    "algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                }
            }
        schema_map[namespace] = {
            "bsonType": "object",
            "properties": properties,
        }

    return schema_map
