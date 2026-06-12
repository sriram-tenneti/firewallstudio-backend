"""MongoDB collection name constants and accessor helpers."""

from motor.motor_asyncio import AsyncIOMotorCollection

from app.db.connection import get_db

# ---- Collection names ----

APPLICATIONS = "applications"
APP_PRESENCES = "app_presences"
SHARED_SERVICES = "shared_services"
SHARED_SERVICE_PRESENCES = "shared_service_presences"

FIREWALL_GROUPS = "firewall_groups"
INGRESS_GROUPS = "ingress_groups"

RULE_REQUESTS = "rule_requests"
PHYSICAL_RULES = "physical_rules"
GROUP_CHANGE_REQUESTS = "group_change_requests"

REQUEST_STATUS_HISTORY = "request_status_history"
AUDIT_TRAIL = "audit_trail"

NEIGHBOURHOODS = "neighbourhoods"
SECURITY_ZONES = "security_zones"
NGDC_DATACENTERS = "ngdc_datacenters"
LEGACY_DATACENTERS = "legacy_datacenters"
ENVIRONMENTS = "environments"
POLICY_MATRIX = "policy_matrix"
NAMING_STANDARDS = "naming_standards"
PORT_CATALOG = "port_catalog"
ORG_CONFIG = "org_config"

MIGRATIONS = "migrations"
MIGRATION_MAPPINGS = "migration_mappings"
MIGRATION_RULE_LIFECYCLE = "migration_rule_lifecycle"

REVIEWS = "reviews"
LIFECYCLE_EVENTS = "lifecycle_events"
ITSM_CONNECTORS = "itsm_connectors"
CHG_REQUESTS = "chg_requests"

FIREWALL_DEVICES = "firewall_devices"
FIREWALL_DEVICE_PATTERNS = "firewall_device_patterns"
DC_VENDOR_MAP = "dc_vendor_map"
APP_DC_MAPPINGS = "app_dc_mappings"


def col(name: str) -> AsyncIOMotorCollection:
    """Shorthand to get a collection handle."""
    return get_db()[name]
