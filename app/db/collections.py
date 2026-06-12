"""Consolidated MongoDB collection names (10 collections).

Optimized from 25+ collections by using type discriminators:
  - reference_data: neighbourhoods, security_zones, DCs, policy, ports, naming
  - groups: firewall + ingress (group_type discriminator)
  - requests: rule + group_change (request_type discriminator)
  - compiled_rules: physical rules for all request types
  - shared_services: shared services + ITSM connectors
  - migrations: migration data + mappings
  - reviews, request_status_history, audit_trail: standalone
  - applications: app registry + presences as nested docs
"""

from motor.motor_asyncio import AsyncIOMotorCollection

from app.db.connection import get_db

# ---- 10 Consolidated Collections ----

APPLICATIONS = "applications"
"""App registry. Each doc has app_distributed_id as _id.
Presences stored as nested array: presences[{dc_id, nh_id, sz_code, environment}]."""

GROUPS = "groups"
"""All group types: firewall and ingress.
Discriminator field: group_type = "firewall" | "ingress"
Ingress groups carry extra vip_entries[] and endpoint_entries[]."""

REQUESTS = "requests"
"""All request types: rule requests and group change requests.
Discriminator field: request_type = "rule" | "group_change"."""

COMPILED_RULES = "compiled_rules"
"""Physical/compiled rules for all request types.
Links back to requests via request_id."""

REFERENCE_DATA = "reference_data"
"""Type-discriminated reference/lookup data.
Discriminator field: ref_type = "neighbourhood" | "security_zone" | "ngdc_datacenter"
  | "legacy_datacenter" | "policy_matrix" | "port_catalog" | "naming_standard"
  | "environment" | "org_config" | "dc_vendor_map" | "device_pattern"."""

REQUEST_STATUS_HISTORY = "request_status_history"
"""Append-only status transitions. Separate for query perf on timeline views.
Keyed by app_distributed_id + request_id."""

AUDIT_TRAIL = "audit_trail"
"""All data mutations with before/after snapshots. Separate for compliance/retention."""

REVIEWS = "reviews"
"""Review/approval workflow records."""

MIGRATIONS = "migrations"
"""Migration data + mappings. Mappings stored as nested docs or sub-array."""

SHARED_SERVICES = "shared_services"
"""Shared service definitions + ITSM connectors.
Discriminator field: service_type = "shared_service" | "itsm_connector" | "chg_request"."""


# ---- Legacy aliases (map old names → new) for backward compatibility ----
# All these resolve to a consolidated collection; queries must include
# the discriminator field (e.g., group_type, request_type, ref_type).

FIREWALL_GROUPS = GROUPS
INGRESS_GROUPS = GROUPS
RULE_REQUESTS = REQUESTS
GROUP_CHANGE_REQUESTS = REQUESTS
PHYSICAL_RULES = COMPILED_RULES
NEIGHBOURHOODS = REFERENCE_DATA
SECURITY_ZONES = REFERENCE_DATA
NGDC_DATACENTERS = REFERENCE_DATA
LEGACY_DATACENTERS = REFERENCE_DATA
POLICY_MATRIX = REFERENCE_DATA
PORT_CATALOG = REFERENCE_DATA
NAMING_STANDARDS = REFERENCE_DATA
ITSM_CONNECTORS = SHARED_SERVICES
MIGRATION_MAPPINGS = MIGRATIONS

# Additional legacy aliases
APP_PRESENCES = APPLICATIONS  # Presences are now nested in applications
SHARED_SERVICE_PRESENCES = SHARED_SERVICES
ENVIRONMENTS = REFERENCE_DATA
ORG_CONFIG = REFERENCE_DATA
LIFECYCLE_EVENTS = AUDIT_TRAIL  # Lifecycle events tracked in audit trail
APP_DC_MAPPINGS = REFERENCE_DATA
MIGRATION_RULE_LIFECYCLE = MIGRATIONS
CHG_REQUESTS = SHARED_SERVICES
FIREWALL_DEVICES = REFERENCE_DATA
FIREWALL_DEVICE_PATTERNS = REFERENCE_DATA
DC_VENDOR_MAP = REFERENCE_DATA


def col(name: str) -> AsyncIOMotorCollection:
    """Shorthand to get a collection handle."""
    return get_db()[name]
