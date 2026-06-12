"""Naming Standards Engine for Network Firewall Studio.

Enforces strict naming conventions for groups, servers, and subnets:
- Groups:  grp-{AppDistributedId}-{NH}-{SZ}-{Subtype}
- Servers: svr-{AppDistributedId}-{NH}-{SZ}-{ServerName}
- Subnets: rng-{AppDistributedId}-{NH}-{SZ}-{Descriptor}

The {APP} placeholder uses the App Distributed Id (e.g. AD-1001) as the
primary identifier. Falls back to App Id if Distributed Id is not available.

Rules must be group-to-group unless an exception is approved.
"""

import re
from typing import Literal

# Valid Neighbourhood IDs
VALID_NH_IDS = [f"NH{i:02d}" for i in range(1, 18)]

# Valid Security Zone codes (Production + Non-Production fabrics)
VALID_SZ_CODES = [
    # Production fabric
    "STD", "GEN", "PAA", "3PY", "CCS", "CDE", "CPA", "PSE", "Swift", "UC",
    # Non-Production fabric
    "UGen", "USTD", "UPAA", "UCPA", "UCDE", "UCCS", "U3PY",
    # Legacy / special
    "DMZ", "RST", "MGT", "PNA", "EPAA", "BCCI", "GGEN", "EPIN",
    "LPAA", "USPP", "EXEN", "SPN", "CPN", "EXT",
]

# Valid Subtypes for groups
VALID_SUBTYPES = {
    "APP": "Application Servers",
    "WEB": "Web Servers",
    "DB": "Database Servers",
    "BAT": "Batch Servers",
    "MQ": "Message Queue",
    "API": "API Servers",
    "LB": "Load Balancers",
    "MON": "Monitoring",
    "MFR": "Mainframe",
    "SVC": "Services",
}

# Naming patterns
GROUP_PATTERN = re.compile(
    r"^grp-([A-Z0-9]+)-(NH\d{2})-((?:" + "|".join(VALID_SZ_CODES) + r"))-([A-Z]{2,4})$",
    re.IGNORECASE,
)
SERVER_PATTERN = re.compile(
    r"^svr-([A-Z0-9]+)-(NH\d{2})-((?:" + "|".join(VALID_SZ_CODES) + r"))-([A-Z0-9_]+)$",
    re.IGNORECASE,
)
SUBNET_PATTERN = re.compile(
    r"^rng-([A-Z0-9]+)-(NH\d{2})-((?:" + "|".join(VALID_SZ_CODES) + r"))-([A-Z0-9_]+)$",
    re.IGNORECASE,
)


def validate_group_name(name: str) -> dict:
    """Validate a group name against naming standards."""
    match = GROUP_PATTERN.match(name)
    if not match:
        return {
            "valid": False,
            "name": name,
            "type": "group",
            "error": f"Group name '{name}' does not match pattern: grp-{{AppID}}-{{NH}}-{{SZ}}-{{Subtype}}",
            "expected_format": "grp-{AppID}-{NHXX}-{SZ}-{Subtype}",
            "example": "grp-CRM-NH02-GEN-APP",
        }

    app_id, nh, sz, subtype = match.groups()
    errors = []

    if nh.upper() not in VALID_NH_IDS:
        errors.append(f"Invalid NH ID '{nh}'. Valid: {', '.join(VALID_NH_IDS)}")
    if sz.upper() not in VALID_SZ_CODES:
        errors.append(f"Invalid SZ code '{sz}'. Valid: {', '.join(VALID_SZ_CODES)}")
    if subtype.upper() not in VALID_SUBTYPES:
        errors.append(f"Invalid Subtype '{subtype}'. Valid: {', '.join(VALID_SUBTYPES.keys())}")

    if errors:
        return {
            "valid": False,
            "name": name,
            "type": "group",
            "error": "; ".join(errors),
            "parsed": {"app_id": app_id, "nh": nh, "sz": sz, "subtype": subtype},
        }

    return {
        "valid": True,
        "name": name,
        "type": "group",
        "parsed": {
            "app_id": app_id.upper(),
            "nh": nh.upper(),
            "sz": sz.upper(),
            "subtype": subtype.upper(),
        },
    }


def validate_server_name(name: str) -> dict:
    """Validate a server name against naming standards."""
    match = SERVER_PATTERN.match(name)
    if not match:
        return {
            "valid": False,
            "name": name,
            "type": "server",
            "error": f"Server name '{name}' does not match pattern: svr-{{AppID}}-{{NH}}-{{SZ}}-{{ServerName}}",
            "expected_format": "svr-{AppID}-{NHXX}-{SZ}-{ServerName}",
            "example": "svr-CRM-NH02-GEN-CRMPROD01",
        }

    app_id, nh, sz, server_name = match.groups()
    errors = []

    if nh.upper() not in VALID_NH_IDS:
        errors.append(f"Invalid NH ID '{nh}'")
    if sz.upper() not in VALID_SZ_CODES:
        errors.append(f"Invalid SZ code '{sz}'")

    if errors:
        return {
            "valid": False,
            "name": name,
            "type": "server",
            "error": "; ".join(errors),
        }

    return {
        "valid": True,
        "name": name,
        "type": "server",
        "parsed": {
            "app_id": app_id.upper(),
            "nh": nh.upper(),
            "sz": sz.upper(),
            "server_name": server_name.upper(),
        },
    }


def validate_subnet_name(name: str) -> dict:
    """Validate a subnet range name against naming standards."""
    match = SUBNET_PATTERN.match(name)
    if not match:
        return {
            "valid": False,
            "name": name,
            "type": "subnet",
            "error": f"Subnet name '{name}' does not match pattern: rng-{{AppID}}-{{NH}}-{{SZ}}-{{Descriptor}}",
            "expected_format": "rng-{AppID}-{NHXX}-{SZ}-{Descriptor}",
            "example": "rng-CRM-NH02-GEN-WEBNET",
        }

    app_id, nh, sz, descriptor = match.groups()
    errors = []

    if nh.upper() not in VALID_NH_IDS:
        errors.append(f"Invalid NH ID '{nh}'")
    if sz.upper() not in VALID_SZ_CODES:
        errors.append(f"Invalid SZ code '{sz}'")

    if errors:
        return {
            "valid": False,
            "name": name,
            "type": "subnet",
            "error": "; ".join(errors),
        }

    return {
        "valid": True,
        "name": name,
        "type": "subnet",
        "parsed": {
            "app_id": app_id.upper(),
            "nh": nh.upper(),
            "sz": sz.upper(),
            "descriptor": descriptor.upper(),
        },
    }


def validate_name(name: str) -> dict:
    """Auto-detect type and validate a name against naming standards."""
    if name.startswith("grp-"):
        return validate_group_name(name)
    elif name.startswith("svr-"):
        return validate_server_name(name)
    elif name.startswith("rng-"):
        return validate_subnet_name(name)
    else:
        return {
            "valid": False,
            "name": name,
            "type": "unknown",
            "error": f"Name '{name}' does not start with a valid prefix (grp-, svr-, rng-)",
            "expected_prefixes": ["grp-", "svr-", "rng-"],
        }


def generate_group_name(app_id: str, nh: str, sz: str, subtype: str) -> dict:
    """Generate a standards-compliant group name."""
    name = f"grp-{app_id.upper()}-{nh.upper()}-{sz.upper()}-{subtype.upper()}"
    result = validate_group_name(name)
    result["generated_name"] = name
    return result


def generate_server_name(app_id: str, nh: str, sz: str, server_name: str) -> dict:
    """Generate a standards-compliant server name."""
    name = f"svr-{app_id.upper()}-{nh.upper()}-{sz.upper()}-{server_name.upper()}"
    result = validate_server_name(name)
    result["generated_name"] = name
    return result


def generate_subnet_name(app_id: str, nh: str, sz: str, descriptor: str) -> dict:
    """Generate a standards-compliant subnet name."""
    name = f"rng-{app_id.upper()}-{nh.upper()}-{sz.upper()}-{descriptor.upper()}"
    result = validate_subnet_name(name)
    result["generated_name"] = name
    return result


def check_group_to_group(source_type: str, dest_type: str) -> dict:
    """Check if a rule follows group-to-group policy. Returns compliance result."""
    source_is_group = source_type.lower() == "group"
    dest_is_group = dest_type.lower() in ("group", "predefined")

    if source_is_group and dest_is_group:
        return {
            "compliant": True,
            "message": "Rule follows group-to-group policy",
            "requires_exception": False,
        }
    else:
        parts = []
        if not source_is_group:
            parts.append(f"source type is '{source_type}' (expected 'Group')")
        if not dest_is_group:
            parts.append(f"destination type is '{dest_type}' (expected 'Group' or 'Predefined')")
        return {
            "compliant": False,
            "message": f"Rule does NOT follow group-to-group policy: {'; '.join(parts)}",
            "requires_exception": True,
            "exception_reason": "Non-group source/destination requires security exception approval",
        }


def suggest_standard_name(
    legacy_name: str,
    app_id: str,
    nh: str = "NH01",
    sz: str = "GEN",
) -> dict:
    """Suggest a standards-compliant name for a legacy resource."""
    # Try to detect the type from the legacy name
    legacy_lower = legacy_name.lower()

    if any(kw in legacy_lower for kw in ["subnet", "net", "range", "cidr"]):
        prefix = "rng"
        # Extract a descriptor from legacy name
        descriptor = re.sub(r"[^A-Z0-9]", "", legacy_name.upper())[:10] or "NET"
        suggested = f"rng-{app_id.upper()}-{nh.upper()}-{sz.upper()}-{descriptor}"
    elif any(kw in legacy_lower for kw in ["srv", "server", "svr", "host"]):
        prefix = "svr"
        server_name = re.sub(r"[^A-Z0-9]", "", legacy_name.upper())[:12] or "SRV01"
        suggested = f"svr-{app_id.upper()}-{nh.upper()}-{sz.upper()}-{server_name}"
    else:
        prefix = "grp"
        # Try to detect subtype
        subtype = "APP"
        if any(kw in legacy_lower for kw in ["db", "database", "sql", "oracle"]):
            subtype = "DB"
        elif any(kw in legacy_lower for kw in ["web", "http", "www"]):
            subtype = "WEB"
        elif any(kw in legacy_lower for kw in ["batch", "job", "cron"]):
            subtype = "BAT"
        elif any(kw in legacy_lower for kw in ["mq", "queue", "kafka"]):
            subtype = "MQ"
        elif any(kw in legacy_lower for kw in ["api", "rest", "service"]):
            subtype = "API"
        suggested = f"grp-{app_id.upper()}-{nh.upper()}-{sz.upper()}-{subtype}"

    validation = validate_name(suggested)

    return {
        "legacy_name": legacy_name,
        "suggested_name": suggested,
        "prefix": prefix,
        "validation": validation,
    }


def determine_security_zone(
    paa_zone: bool = False,
    exposure: str = "Internal",
    pci_pan: bool = False,
    pci_track_data: bool = False,
    pci_cvv_pin: bool = False,
    deployment_type: str = "ON_PREMISE",
    critical_payment: bool = False,
    data_classification: str = "INTERNAL",
    criticality_rating: int = 3,
    environment: str = "Production",
) -> dict:
    """Determine the security zone based on NGDC business logic decision tree."""

    if environment == "Production":
        # PAA Zone check
        if paa_zone and exposure == "Internet":
            return {
                "neighbourhood_type": "DMZ",
                "security_zone": "PNA",
                "reason": "PAA Zone = YES AND @Exposure = Internet",
            }

        if paa_zone:
            # PCI checks
            if pci_pan or pci_track_data or pci_cvv_pin:
                return {
                    "neighbourhood_type": "Production",
                    "security_zone": "CDE",
                    "reason": "PAA Zone with PCI data attributes",
                }

        # ECPA Deployment Type
        if deployment_type == "ECPA":
            return {
                "neighbourhood_type": "Production",
                "security_zone": "UCPA",
                "reason": "Deployment Type = ECPA (Enterprise Critical Payment)",
            }

        # Critical Payment
        if critical_payment:
            return {
                "neighbourhood_type": "Production",
                "security_zone": "CPN",
                "reason": "Enterprise Critical Payment Application = YES",
            }

        # Data Classification
        if data_classification in ("CONFIDENTIAL", "RESTRICTED"):
            if criticality_rating == 1:
                return {
                    "neighbourhood_type": "Production",
                    "security_zone": "BCCI",
                    "reason": "Confidential/Restricted data with Most Critical rating",
                }
            return {
                "neighbourhood_type": "Production",
                "security_zone": "RST",
                "reason": f"Data Classification = {data_classification}",
            }

        # Default
        return {
            "neighbourhood_type": "Production",
            "security_zone": "GEN",
            "reason": "Server does not meet any prior criteria - General zone",
        }

    else:
        # Non-Production
        if paa_zone and exposure == "Internet":
            return {
                "neighbourhood_type": "Non-Production DMZ",
                "security_zone": "PNA",
                "reason": "Non-Prod: PAA Zone = YES AND @Exposure = Internet",
            }

        if paa_zone:
            return {
                "neighbourhood_type": "Non-Production Shared",
                "security_zone": "GEN",
                "reason": "Non-Prod: PAA Zone app in shared environment",
            }

        return {
            "neighbourhood_type": "Non-Production Shared",
            "security_zone": "GEN",
            "reason": "Non-Production default zone",
        }


def get_naming_standards_info() -> dict:
    """Return the full naming standards reference info."""
    return {
        "prefixes": {
            "grp": {
                "description": "Group (collection of servers)",
                "pattern": "grp-{AppDistributedId}-{NH}-{SZ}-{Subtype}",
                "example": "grp-AD-1001-NH02-CCS-APP",
            },
            "svr": {
                "description": "Individual server/IP",
                "pattern": "svr-{AppDistributedId}-{NH}-{SZ}-{ServerName}",
                "example": "svr-AD-1001-NH02-CCS-CRMPROD01",
            },
            "rng": {
                "description": "Subnet/IP range",
                "pattern": "rng-{AppDistributedId}-{NH}-{SZ}-{Descriptor}",
                "example": "rng-AD-1001-NH02-CCS-WEBNET",
            },
        },
        "valid_nh_ids": VALID_NH_IDS,
        "valid_sz_codes": VALID_SZ_CODES,
        "valid_subtypes": VALID_SUBTYPES,
        "enforcement_rules": [
            "All firewall rules MUST be group-to-group by default",
            "Non-group rules require security exception approval",
            "All names must follow the naming convention with valid NH, SZ, and Subtype",
            "Legacy names must be migrated to standards-compliant names",
            "Naming validation is enforced at rule creation and migration time",
        ],
    }
