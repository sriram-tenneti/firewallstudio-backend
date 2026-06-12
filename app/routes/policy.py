"""Policy validation endpoint."""

from fastapi import APIRouter

from app.db.collections import col, POLICY_MATRIX

router = APIRouter(prefix="/api/policy", tags=["Policy Validation"])


@router.post("/validate")
async def validate_policy(data: dict):
    """Validate a rule against the policy matrix.

    Checks source_zone → dest_zone permission against the policy matrix.
    """
    source_zone = data.get("source_zone", "")
    dest_zone = data.get("dest_zone", "")
    environment = data.get("environment", "Production")

    if not source_zone or not dest_zone:
        return {
            "result": "Needs Review",
            "message": "Source and destination zones required for policy check",
            "details": [],
            "ngdc_zone_check": False,
            "birthright_compliant": False,
        }

    entry = await col(POLICY_MATRIX).find_one({
        "source_zone": source_zone,
        "dest_zone": dest_zone,
    })

    if not entry:
        return {
            "result": "Needs Review",
            "message": f"No policy entry for {source_zone} → {dest_zone}",
            "details": [f"Zone pair not found in policy matrix"],
            "ngdc_zone_check": False,
            "birthright_compliant": False,
        }

    action = entry.get("default_action", "Block")
    requires_exception = entry.get("requires_exception", False)

    if action == "Allow" and not requires_exception:
        return {
            "result": "Permitted",
            "message": f"{source_zone} → {dest_zone}: Permitted",
            "details": [],
            "ngdc_zone_check": True,
            "birthright_compliant": True,
        }
    elif requires_exception:
        return {
            "result": "Exception Required",
            "message": f"{source_zone} → {dest_zone}: Exception required",
            "details": [entry.get("description", "")],
            "ngdc_zone_check": True,
            "birthright_compliant": False,
        }
    else:
        return {
            "result": "Blocked",
            "message": f"{source_zone} → {dest_zone}: Blocked by policy",
            "details": [entry.get("description", "")],
            "ngdc_zone_check": True,
            "birthright_compliant": False,
        }
