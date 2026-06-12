"""Firewall Group and enhanced Ingress Group models."""

from typing import Optional

from pydantic import BaseModel

from app.models.base import AuditMixin
from app.models.applications import MemberSpec


class FirewallGroupOwnerKind(str):
    APP_EGRESS = "app_egress"
    APP_INGRESS = "app_ingress"
    SHARED_SERVICE = "shared_service"
    ADHOC_DESTINATION = "adhoc_destination"


class FirewallGroup(AuditMixin):
    """Unified firewall group.

    _id in MongoDB = group name (e.g. grp-AD-1001-WEB-NH06-CDE).
    """
    name: str
    app_distributed_id: Optional[str] = None
    owner_kind: str = "app_egress"
    owner_ref: Optional[str] = None
    dc_id: Optional[str] = None
    environment: str = "Production"
    nh_id: Optional[str] = None
    sz_code: Optional[str] = None
    direction: str = "egress"  # "egress" | "ingress"
    members: list[MemberSpec] = []
    description: str = ""


# ---- Enhanced Ingress Group (new) ----

class VIPEntry(BaseModel):
    """Virtual IP reference — for documentation, NOT rule compilation."""
    vip_address: str = ""        # ENCRYPTED
    vip_name: str = ""
    load_balancer: str = ""
    pool_members: list[str] = []
    description: str = ""


class EndpointEntry(BaseModel):
    """DNS/FQDN/Service endpoint reference — for documentation, NOT rule compilation."""
    endpoint_name: str = ""      # ENCRYPTED
    endpoint_type: str = "DNS"   # "DNS" | "FQDN" | "Service"
    resolved_ips: list[str] = []
    description: str = ""
    last_resolved_at: Optional[str] = None


class IngressGroup(AuditMixin):
    """Enhanced ingress group with VIP and endpoint reference support.

    _id in MongoDB = group name (e.g. grp-AD-1001-WEB-NH06-CDE-Ingress).
    """
    name: str
    app_distributed_id: Optional[str] = None
    dc_id: Optional[str] = None
    environment: str = "Production"
    nh_id: Optional[str] = None
    sz_code: Optional[str] = None
    direction: str = "ingress"

    # Standard members — used in rule compilation
    members: list[MemberSpec] = []

    # VIP references — NOT used in rule compilation, documentation only
    vip_entries: list[VIPEntry] = []

    # Endpoint references — NOT used in rule compilation, documentation only
    endpoint_entries: list[EndpointEntry] = []

    description: str = ""
