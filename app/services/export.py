"""XLSX export service — builds spreadsheet rows from manifests.

The 'Destination Host' column shows VIP addresses or endpoint names
from the ingress_groups collection when a destination group is an
ingress group. Per user requirement: "for ingress groups, there should
be provision to add the ip addresses along with the vips or endpoint
names — may not be used in the rule compile but for references."
"""

from typing import Any

from app.db.collections import col, INGRESS_GROUPS


async def resolve_group_members(name: str) -> list[str]:
    """Look up group members from the firewall_groups or ingress_groups collection."""
    from app.db.collections import FIREWALL_GROUPS

    if not name:
        return []

    # Try ingress_groups first, then firewall_groups
    doc = await col(INGRESS_GROUPS).find_one({"name": name})
    if not doc:
        doc = await col(FIREWALL_GROUPS).find_one({"name": name})

    if doc:
        members = doc.get("members", [])
        return [str(m.get("value", m) if isinstance(m, dict) else m) for m in members]
    return []


async def resolve_destination_host(name: str) -> str:
    """Resolve VIP or endpoint name for a destination group.

    Returns a multi-line string with VIP addresses and endpoint names
    from the ingress_groups collection. This is the value shown in the
    'Destination Host' column in downloadable spreadsheets.

    Returns empty string if the group has no VIP/endpoint entries.
    """
    if not name:
        return ""

    doc = await col(INGRESS_GROUPS).find_one({"name": name})
    if not doc:
        return ""

    lines: list[str] = []

    # VIP entries
    for vip in doc.get("vip_entries", []):
        vip_addr = vip.get("vip_address", "")
        vip_name = vip.get("vip_name", "")
        lb = vip.get("load_balancer", "")
        if vip_addr or vip_name:
            label = vip_name or vip_addr
            if lb:
                label = f"{label} ({lb})"
            lines.append(f"VIP: {label}")
            if vip_addr and vip_name:
                lines.append(f"  Address: {vip_addr}")

    # Endpoint entries
    for ep in doc.get("endpoint_entries", []):
        ep_name = ep.get("endpoint_name", "")
        ep_type = ep.get("endpoint_type", "DNS")
        if ep_name:
            lines.append(f"{ep_type}: {ep_name}")
            resolved = ep.get("resolved_ips", [])
            if resolved:
                for ip in resolved:
                    lines.append(f"  → {ip}")

    return "\n".join(lines)


def _expansion_block(group_name: str, members: list[str]) -> str:
    """Build multi-line expansion cell: group name + indented members."""
    if not group_name:
        return ""
    lines = [str(group_name)]
    for m in members:
        lines.append(f"  {m}")
    return "\n".join(lines)


async def build_xlsx_rows(manifest: dict[str, Any]) -> dict[str, list[list[str]]]:
    """Flatten manifest into spreadsheet rows.

    Returns { sheet_name: [[header_row], [...data...]] }.

    Key enhancement: 'Destination Host' column shows VIP/endpoint names
    from the ingress_groups collection for reference purposes.
    """
    # Pre-resolve groups
    member_index: dict[str, list[str]] = {}
    for g in manifest.get("groups", []) or []:
        gn = str(g.get("name", ""))
        if gn and g.get("members"):
            member_index[gn.upper()] = [
                str(m.get("value", m) if isinstance(m, dict) else m)
                for m in g["members"]
            ]

    async def _members_for(name: str) -> list[str]:
        if not name:
            return []
        cached = member_index.get(name.upper())
        if cached is not None:
            return cached
        resolved = await resolve_group_members(name)
        member_index[name.upper()] = resolved
        return resolved

    # Build rules sheet — now with 'Destination Host' column
    rules_sheet: list[list[str]] = [[
        "rule_id", "vrf", "src_dc", "dst_dc",
        "src_group", "dst_group",
        "src_nh", "src_sz", "dst_nh", "dst_sz",
        "protocol", "ports", "action", "lifecycle_status",
        "Source Expansion", "Destination Expansion",
        "Destination Host",  # VIP/endpoint reference
    ]]

    for r in manifest.get("rules", []):
        src_g = str(r.get("src_group", ""))
        dst_g = str(r.get("dst_group", ""))
        src_members = await _members_for(src_g)
        dst_members = await _members_for(dst_g)
        dst_host = await resolve_destination_host(dst_g)

        rules_sheet.append([
            str(r.get("rule_id", "")),
            str(r.get("vrf", "")),
            str(r.get("src_dc", "")),
            str(r.get("dst_dc", "")),
            src_g,
            dst_g,
            str(r.get("src_nh", "")),
            str(r.get("src_sz", "")),
            str(r.get("dst_nh", "")),
            str(r.get("dst_sz", "")),
            str(r.get("protocol", "")),
            str(r.get("ports", "")),
            str(r.get("action", "")),
            str(r.get("lifecycle_status", "")),
            _expansion_block(src_g, src_members),
            _expansion_block(dst_g, dst_members),
            dst_host,  # Destination Host = VIP/endpoint from ingress group
        ])

    # Groups sheet
    groups_sheet: list[list[str]] = [["group", "op", "members", "added_members", "removed_members"]]
    for g in manifest.get("groups", []):
        members_raw = g.get("members") or []
        groups_sheet.append([
            str(g.get("name", "")),
            str(g.get("op", "")),
            "\n".join(str(m.get("value", m) if isinstance(m, dict) else m) for m in members_raw),
            "\n".join(str(m) for m in (g.get("added_members") or [])),
            "\n".join(str(m) for m in (g.get("removed_members") or [])),
        ])

    # Summary sheet
    summary_sheet: list[list[str]] = [
        ["field", "value"],
        ["request_id", str(manifest.get("request_id") or "")],
        ["requester", str(manifest.get("requester") or "")],
        ["owner_team", str(manifest.get("owner_team") or "")],
        ["environment", str(manifest.get("environment") or "")],
        ["vrf", str(manifest.get("vrf") or "")],
        ["status", str(manifest.get("status") or "")],
        ["external_ticket_id", str(manifest.get("external_ticket_id") or "")],
        ["external_ticket_url", str(manifest.get("external_ticket_url") or "")],
    ]

    return {
        "Summary": summary_sheet,
        "Rules": rules_sheet,
        "Groups": groups_sheet,
    }
