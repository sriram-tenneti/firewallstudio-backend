"""Request status tracking models — separate collection for state transitions."""

from typing import Optional

from pydantic import BaseModel

from app.models.base import AuditMixin


class RequestStatusEntry(BaseModel):
    """One state transition in the request_status_history collection.

    Keyed by app_distributed_id for efficient per-app queries.
    """
    app_distributed_id: str
    request_id: str
    request_type: str  # "rule_request" | "group_change" | "modification"
    from_status: str
    to_status: str
    transitioned_at: str
    transitioned_by: str = ""  # ENCRYPTED
    module: str = "design-studio"
    comments: str = ""
    metadata: dict = {}


# State machine definitions

REQUEST_STATE_MACHINE: dict[str, list[str]] = {
    "Draft": ["Submitted"],
    "Submitted": ["In Progress", "Rejected"],
    "In Progress": ["Approved", "Rejected"],
    "Approved": ["Deployed", "Rejected"],
    "Rejected": ["Submitted"],
    "Deployed": ["Certified", "Decommissioning"],
    "Certified": ["Expired", "Decommissioning", "Deployed"],
    "Expired": ["Certified", "Decommissioning"],
    "Decommissioning": ["Decommissioned"],
    "Decommissioned": [],
}

# Legacy rules start deployed
LEGACY_STATE_MACHINE: dict[str, list[str]] = {
    "Deployed": ["Certified", "Decommissioning"],
    "Certified": ["Expired", "Decommissioning", "Deployed"],
    "Expired": ["Certified", "Decommissioning"],
    "Decommissioning": ["Decommissioned"],
    "Decommissioned": [],
}

# Group change request states
GROUP_REQUEST_STATE_MACHINE: dict[str, list[str]] = {
    "Pending": ["Approved", "Rejected"],
    "Approved": ["Deployed"],
    "Rejected": ["Pending"],
    "Deployed": ["Certified"],
    "Certified": [],
}


def get_valid_transitions(
    current_status: str,
    is_legacy: bool = False,
    request_type: str = "rule_request",
) -> list[str]:
    """Return valid next states."""
    if request_type == "group_change":
        machine = GROUP_REQUEST_STATE_MACHINE
    elif is_legacy:
        machine = LEGACY_STATE_MACHINE
    else:
        machine = REQUEST_STATE_MACHINE
    return machine.get(current_status, [])


def is_valid_transition(
    current_status: str,
    new_status: str,
    is_legacy: bool = False,
    request_type: str = "rule_request",
) -> bool:
    """Check if a status transition is valid."""
    return new_status in get_valid_transitions(current_status, is_legacy, request_type)
