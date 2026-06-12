"""Application and Shared Service profile models."""

from typing import Optional, Literal

from pydantic import BaseModel, Field

from app.models.base import AuditMixin


class MemberType(str):
    IP = "ip"
    CIDR = "cidr"
    SUBNET = "subnet"
    RANGE = "range"
    GROUP = "group"


class MemberSpec(BaseModel):
    type: str = "ip"
    value: str
    description: str = ""
    dc_id: Optional[str] = None


class PortBinding(BaseModel):
    port_id: Optional[str] = None
    protocol: Optional[Literal["TCP", "UDP", "ICMP"]] = None
    port: Optional[int] = None
    label: str = ""


class TierSpec(BaseModel):
    nh_id: str
    sz_code: str
    has_ingress: bool = False
    label: str = ""


class HeritageTierSpec(BaseModel):
    dc_id: str
    has_ingress: bool = False
    label: str = ""


class AppPresence(AuditMixin):
    """Per-(DC, NH, SZ) presence of an Application."""
    app_distributed_id: str
    dc_id: str
    dc_type: Literal["NGDC", "Legacy"] = "NGDC"
    environment: str = "Production"
    nh_id: str
    sz_code: str
    has_ingress: bool = False
    egress_members: list[MemberSpec] = []
    ingress_members: list[MemberSpec] = []
    ingress_ports: list[PortBinding] = []


class ApplicationProfile(AuditMixin):
    """Top-level Application metadata.

    _id in MongoDB = app_distributed_id (natural key).
    """
    app_distributed_id: str
    app_id: Optional[str] = None
    name: str = ""
    owner: str = ""
    owner_team: str = ""
    description: str = ""
    criticality: str = "Medium"
    pci_scope: bool = False
    components: list[str] = []
    primary_dc: str = "ALPHA_NGDC"
    deployment_mode: str = "all_ngdc"
    excluded_dcs: list[str] = []
    tiers: list[TierSpec] = []
    heritage_tiers: list[HeritageTierSpec] = Field(
        default_factory=list, alias="legacy_tiers"
    )
    environments: list[str] = ["Production"]

    model_config = {"populate_by_name": True}


class SharedServiceCategory(str):
    MESSAGING = "Messaging"
    DATABASE = "Database"
    OBSERVABILITY = "Observability"
    IDENTITY = "Identity"
    CACHE = "Cache"
    OTHER = "Other"


class SharedServicePresence(AuditMixin):
    service_id: str
    dc_id: str
    dc_type: Literal["NGDC", "Legacy"] = "NGDC"
    environment: str = "Production"
    nh_id: str
    sz_code: str
    members: list[MemberSpec] = []


class SharedService(AuditMixin):
    service_id: str
    name: str
    category: str = "Other"
    owner: str = ""
    owner_team: str = "SNS"
    description: str = ""
    icon: str = ""
    color: str = ""
    environments: list[str] = ["Production"]
    tags: list[str] = []
    primary_dc: str = "ALPHA_NGDC"
    deployment_mode: str = "all_ngdc"
    excluded_dcs: list[str] = []
    tiers: list[TierSpec] = []
    heritage_tiers: list[HeritageTierSpec] = Field(
        default_factory=list, alias="legacy_tiers"
    )
    standard_ports: list[str] = []
    additional_ports: list[PortBinding] = []

    model_config = {"populate_by_name": True}
