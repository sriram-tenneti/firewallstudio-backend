"""Audit trail entry model."""

from typing import Optional

from pydantic import BaseModel


class AuditTrailEntry(BaseModel):
    """Every data mutation generates one of these in the audit_trail collection."""
    app_distributed_id: Optional[str] = None
    collection: str
    document_id: str
    operation: str  # "create" | "update" | "delete"
    user_id: str = ""           # ENCRYPTED
    user_email: str = ""        # ENCRYPTED
    user_team: str = ""
    timestamp: str
    before_snapshot: Optional[dict] = None  # ENCRYPTED
    after_snapshot: Optional[dict] = None   # ENCRYPTED
    changed_fields: list[str] = []
    ip_address: str = ""
    request_id: str = ""
    module: str = ""
