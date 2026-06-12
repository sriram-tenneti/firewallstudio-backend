"""Rule-related models: RuleRequest, PhysicalRule, FirewallRule, etc."""

from typing import Optional, Literal

from pydantic import BaseModel

from app.models.base import AuditMixin
from app.models.applications import MemberSpec


# ---- Source / Destination entity kinds ----

class SourceEntityKind(str):
    APP = "app"
    SHARED_SERVICE = "shared_service"


class DestinationEntityKind(str):
    APP_INGRESS = "app_ingress"
    SHARED_SERVICE = "shared_service"
    ADHOC = "adhoc"


# ---- Rule Request (logical) ----

class RuleRequestCreate(BaseModel):
    """Payload for creating a new logical rule request."""
    source_kind: str = "app"
    source_ref: Optional[str] = None
    application_ref: str = ""
    destination_kind: str  # "app_ingress" | "shared_service" | "adhoc"
    destination_ref: Optional[str] = None
    environment: str = "Production"
    ports: str = "TCP 8080"
    action: Literal["ACCEPT", "DROP"] = "ACCEPT"
    description: str = ""
    src_members_override: list[MemberSpec] = []
    dst_members_override: list[MemberSpec] = []
    requested_dcs: Optional[list[str]] = None
    source_presences: Optional[list[dict]] = None
    destination_presences: Optional[list[dict]] = None
    include_cross_dc: bool = False
    destination_dc_override: Optional[str] = None
    owner: str = ""
    owner_team: str = ""


class RuleRequestRecord(AuditMixin):
    """Persisted rule request document in MongoDB."""
    request_id: str
    app_distributed_id: str
    source_kind: str = "app"
    source_ref: Optional[str] = None
    application_ref: str = ""
    destination_kind: str
    destination_ref: Optional[str] = None
    environment: str = "Production"
    ports: str = ""
    action: str = "ACCEPT"
    description: str = ""
    owner: str = ""  # ENCRYPTED
    owner_team: str = ""
    status: str = "Draft"
    expansion: list[str] = []  # physical rule _ids
    # ITSM ticket references
    external_tickets: list[dict] = []


class PhysicalRule(AuditMixin):
    """Per-DC physical rule generated from fan-out."""
    rule_id: str
    request_id: str
    app_distributed_id: str
    src_dc: str
    dst_dc: str
    src_group_ref: str
    dst_group_ref: str
    src_nh: Optional[str] = None
    src_sz: Optional[str] = None
    dst_nh: Optional[str] = None
    dst_sz: Optional[str] = None
    ports: str = ""
    action: str = "ACCEPT"
    environment: str = "Production"
    policy_result: Optional[str] = None
    compiled_text: Optional[str] = None  # ENCRYPTED
    lifecycle_status: str = "Submitted"


# ---- Legacy FirewallRule (backward compat for existing rules table) ----

class SourceConfig(BaseModel):
    source_type: str = "Single IP"
    ip_address: Optional[str] = None
    cidr: Optional[str] = None
    group_name: Optional[str] = None
    ports: str = "TCP 8080"
    neighbourhood: Optional[str] = None
    security_zone: Optional[str] = None


class DestinationConfig(BaseModel):
    name: str
    security_zone: Optional[str] = None
    dest_ip: Optional[str] = None
    ports: str = "TCP 8443"
    is_predefined: bool = True


class FirewallRule(AuditMixin):
    rule_id: str
    application: str = ""
    app_distributed_id: str = ""
    environment: str = "Production"
    datacenter: str = ""
    source: SourceConfig = SourceConfig()
    destination: DestinationConfig = DestinationConfig(name="")
    policy_result: str = "Permitted"
    status: str = "Draft"
    rule_status: str = "Submitted"
    rule_migration_status: str = "Not Migrated"
    expiry: Optional[str] = None
    owner: str = ""
    certified_at: Optional[str] = None
    certified_by: Optional[str] = None
    description: str = ""
    action: str = "ACCEPT"


# ---- Group Change Request ----

class GroupChangeRequest(AuditMixin):
    request_id: str
    app_distributed_id: str
    group_name: str
    change_type: str = "create"  # "create" | "modify" | "delete"
    environment: str = "Production"
    members: list[MemberSpec] = []
    description: str = ""
    owner: str = ""
    owner_team: str = ""
    status: str = "Pending"


# ---- Policy validation ----

class PolicyValidationRequest(BaseModel):
    source: SourceConfig
    destination: DestinationConfig
    application: str = ""
    environment: str = "Production"


class PolicyValidationResult(BaseModel):
    result: str  # "Permitted" | "Blocked" | "Exception Required" | "Needs Review"
    message: str
    details: list[str] = []
    ngdc_zone_check: bool = True
    birthright_compliant: bool = True


# ---- CHG Request ----

class CHGRequest(AuditMixin):
    chg_number: str
    rule_ids: list[str] = []
    migration_id: Optional[str] = None
    status: str = "Open"
    description: str = ""


# ---- Rule History ----

class RuleHistoryEntry(BaseModel):
    rule_id: str
    action: str
    timestamp: str
    user: str
    details: str = ""
