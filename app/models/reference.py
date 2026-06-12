"""Reference data models — Neighbourhoods, Security Zones, DCs, Policy, etc."""

from typing import Optional, Literal

from pydantic import BaseModel

from app.models.base import AuditMixin


class Environment(str):
    PRODUCTION = "Production"
    NON_PRODUCTION = "Non-Production"
    PRE_PRODUCTION = "Pre-Production"


class Neighbourhood(BaseModel):
    nh_id: str
    name: str
    zone: str = ""
    environment: str = "Production"
    description: str = ""
    ip_ranges: list[dict] = []
    subnets: list[str] = []


class SecurityZone(BaseModel):
    code: str
    name: str
    description: str = ""
    naming_mode: str = "app_scoped"  # "app_scoped" | "zone_scoped"
    risk_level: str = ""
    pci_scope: bool = False
    ip_ranges: list[dict] = []


class NGDCDataCenter(BaseModel):
    code: str
    name: str
    neighbourhoods: list[dict] = []
    ip_groups: list[dict] = []
    rule_count: int = 0


class LegacyDataCenter(BaseModel):
    code: str
    name: str


class EnvironmentEntry(BaseModel):
    code: str
    name: str
    description: str = ""


class PredefinedDestination(BaseModel):
    name: str
    security_zone: str
    description: str = ""
    friendly_name: str = ""


class PolicyMatrixEntry(BaseModel):
    source_zone: str
    dest_zone: str
    default_action: str
    requires_exception: bool = False
    description: str = ""


class NamingStandard(BaseModel):
    prefixes: dict = {}
    valid_nh_ids: list[str] = []
    valid_sz_codes: list[str] = []
    valid_subtypes: dict = {}
    enforcement_rules: list[str] = []


class PortCatalogEntry(BaseModel):
    port_id: str
    protocol: Literal["TCP", "UDP", "ICMP"] = "TCP"
    port: int
    label: str = ""
    description: str = ""
    category: str = ""


class OrgConfig(BaseModel):
    org_name: str = ""
    org_code: str = ""
    servicenow_instance: str = ""
    servicenow_api_path: str = ""
    gitops_repo: str = ""
    gitops_branch: str = "main"
    approval_required: bool = True
    auto_certify_birthright: bool = False
    notification_email: str = ""
    notification_slack_channel: str = ""
    max_rule_expiry_days: int = 365
    enforce_group_to_group: bool = True


class FirewallDevice(BaseModel):
    device_id: str
    name: str
    vendor: str = ""
    dc_id: str = ""
    management_ip: str = ""


class ITSMConnectorKind(str):
    SERVICENOW = "servicenow"
    JIRA = "jira"
    GENERIC_REST = "generic_rest"


class ITSMAuthMode(str):
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"
    VAULT = "vault"


class ITSMConnector(AuditMixin):
    connector_id: str
    name: str
    kind: str = "generic_rest"
    enabled: bool = True
    environments: list[str] = ["Production"]
    base_url: str = ""
    table: Optional[str] = "change_request"
    submit_path: Optional[str] = None
    status_path_template: Optional[str] = None
    auth_mode: str = "api_key"
    auth_secret_ref: Optional[str] = None
    auth_config: dict = {}  # ENCRYPTED
    vault_path: Optional[str] = None
    vault_field: Optional[str] = None
    payload_template: dict = {}
    field_mapping: dict = {}
    status_field: str = "state"
    closed_states: list[str] = ["Closed", "Closed Complete", "Closed Successful", "Resolved"]
    rejected_states: list[str] = ["Cancelled", "Closed Incomplete", "Closed Rejected"]
    auto_submit_on_approval: bool = False
    poll_interval_seconds: int = 900
    notes: str = ""
