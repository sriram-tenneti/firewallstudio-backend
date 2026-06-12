"""Pass-Through Validation API routes.

Endpoints:
  POST /api/validation/single     — Single source→destination check (policy + live)
  POST /api/validation/bulk       — Bulk validation (CSV/list, parallel probes)
  POST /api/validation/resolve    — Resolve an entity to IPs/groups (helper)
  GET  /api/validation/config     — Get current probe configuration
  PUT  /api/validation/config     — Update probe configuration
  GET  /api/validation/methods    — List available probe methods
  POST /api/validation/export     — Export bulk results as XLSX
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query
from pydantic import BaseModel, Field

from app.db.store import get_store
from app.db.collections import REFERENCE_DATA, AUDIT_TRAIL
from app.services.validation import (
    EntityType,
    PolicyVerdict,
    LiveVerdict,
    OverallVerdict,
    validate_pass_through,
    validate_bulk,
    resolve_entity,
    detect_entity_type,
)
from app.services.probes import (
    ProbeMethod,
    ProbeConfig,
    load_probe_config,
)

router = APIRouter(prefix="/api/validation", tags=["Pass-Through Validation"])


# ---- Request/Response Models ----

class SingleValidationRequest(BaseModel):
    source: str = Field(..., description="Source entity (IP, group, VM, OCP ref, FQDN)")
    destination: str = Field(..., description="Destination entity")
    ports: list[str] = Field(..., description="Ports to check (e.g., ['tcp/443', '8080'])")
    environment: str | None = Field(None, description="Environment filter (Production, Non-Production, Pre-Production)")
    source_type: str | None = Field(None, description="Force source entity type (ip, cidr, group, vm, ocp_pod, ocp_service, ocp_route, fqdn)")
    destination_type: str | None = Field(None, description="Force destination entity type")
    live_check: bool = Field(True, description="Run live connectivity probes (True) or policy-only (False)")
    timeout: float = Field(5.0, description="Timeout per probe in seconds")
    probe_methods: list[str] | None = Field(None, description="Override probe methods to use")


class BulkValidationRequest(BaseModel):
    checks: list[dict] = Field(..., description="List of {source, destination, ports} dicts")
    environment: str | None = None
    live_check: bool = True
    timeout: float = 5.0
    max_concurrent: int = Field(10, le=50, description="Max parallel probes")


class ResolveRequest(BaseModel):
    entity: str = Field(..., description="Entity to resolve")
    entity_type: str | None = Field(None, description="Force type")


class ProbeConfigUpdate(BaseModel):
    enabled_methods: list[str] | None = None
    fallback_order: list[str] | None = None
    disabled_methods: list[str] | None = None
    timeout_seconds: float | None = None
    max_concurrent_probes: int | None = None
    firewall_api: dict | None = None
    ocp_api: dict | None = None


# ---- Endpoints ----

@router.post("/single")
async def validate_single(req: SingleValidationRequest):
    """Validate a single source → destination pass-through.

    Performs:
    1. Entity resolution (source + destination → IPs, groups, zones)
    2. Policy check (compiled rules + policy matrix)
    3. Live probe (TCP/ICMP/HTTP/Firewall API based on config)
    4. Drift detection (policy vs live mismatch)
    """
    src_type = EntityType(req.source_type) if req.source_type else None
    dst_type = EntityType(req.destination_type) if req.destination_type else None

    result = await validate_pass_through(
        source=req.source,
        destination=req.destination,
        ports=req.ports,
        environment=req.environment,
        source_type=src_type,
        destination_type=dst_type,
        live_check=req.live_check,
        timeout=req.timeout,
    )

    # Log validation to audit trail
    await _log_validation(
        action="single_validation",
        source=req.source,
        destination=req.destination,
        ports=req.ports,
        result=result.overall_verdict.value,
    )

    return result.to_dict()


@router.post("/bulk")
async def validate_bulk_endpoint(req: BulkValidationRequest):
    """Validate multiple source → destination checks in parallel.

    Accepts a list of checks and runs them concurrently with configurable
    parallelism. Returns results in order with index.
    """
    if len(req.checks) > 500:
        raise HTTPException(400, "Maximum 500 checks per bulk request")

    results = await validate_bulk(
        checks=req.checks,
        environment=req.environment,
        live_check=req.live_check,
        timeout=req.timeout,
        max_concurrent=req.max_concurrent,
    )

    # Summary stats
    verdicts = {}
    for r in results:
        v = r.get("overall_verdict", "UNKNOWN")
        verdicts[v] = verdicts.get(v, 0) + 1

    # Log bulk validation
    await _log_validation(
        action="bulk_validation",
        source=f"{len(req.checks)} checks",
        destination="bulk",
        ports=[],
        result=str(verdicts),
    )

    return {
        "total": len(results),
        "summary": verdicts,
        "results": results,
    }


@router.post("/bulk/upload")
async def validate_bulk_csv(
    file: UploadFile = File(...),
    environment: str | None = Form(None),
    live_check: bool = Form(True),
    timeout: float = Form(5.0),
):
    """Upload CSV for bulk validation.

    CSV format: source,destination,ports
    Example:
      10.20.30.10,10.50.60.10,tcp/443
      grp-CRM-WEB-NH02-GEN,grp-PAY-API-NH14-PAA,tcp/443 tcp/8443
      vm-web-01,svc/payments/payment-svc,tcp/8080
    """
    content = await file.read()
    text = content.decode("utf-8")
    reader = csv.reader(io.StringIO(text))

    checks: list[dict] = []
    for row in reader:
        if len(row) < 3:
            continue
        # Skip header row
        if row[0].lower().strip() in ("source", "src", "source_host"):
            continue
        checks.append({
            "source": row[0].strip(),
            "destination": row[1].strip(),
            "ports": [p.strip() for p in row[2].replace(",", " ").split() if p.strip()],
        })

    if not checks:
        raise HTTPException(400, "No valid rows found in CSV")
    if len(checks) > 500:
        raise HTTPException(400, "Maximum 500 rows per upload")

    results = await validate_bulk(
        checks=checks,
        environment=environment,
        live_check=live_check,
        timeout=timeout,
    )

    verdicts = {}
    for r in results:
        v = r.get("overall_verdict", "UNKNOWN")
        verdicts[v] = verdicts.get(v, 0) + 1

    return {
        "total": len(results),
        "summary": verdicts,
        "results": results,
    }


@router.post("/resolve")
async def resolve_entity_endpoint(req: ResolveRequest):
    """Resolve an entity to IPs and groups (helper/debug endpoint).

    Useful for testing entity resolution before running full validation.
    """
    etype = EntityType(req.entity_type) if req.entity_type else None
    entity = await resolve_entity(req.entity, etype)

    return {
        "input": entity.original_input,
        "detected_type": entity.entity_type.value,
        "resolved_ips": entity.resolved_ips,
        "matched_groups": entity.matched_groups,
        "nh_id": entity.nh_id,
        "sz_code": entity.sz_code,
        "dc_id": entity.dc_id,
        "environment": entity.environment,
        "notes": entity.resolution_notes,
    }


@router.get("/config")
async def get_probe_config():
    """Get current organization probe configuration."""
    config = await load_probe_config()
    return {
        "enabled_methods": [m.value for m in config.enabled_methods],
        "fallback_order": [m.value for m in config.fallback_order],
        "disabled_methods": [m.value for m in config.disabled_methods],
        "timeout_seconds": config.timeout_seconds,
        "max_concurrent_probes": config.max_concurrent_probes,
        "firewall_api": {
            "provider": config.firewall_provider,
            "base_url": config.firewall_api_url,
            "configured": bool(config.firewall_api_key_env),
        },
        "ocp_api": {
            "base_url": config.ocp_api_url,
            "configured": bool(config.ocp_token_env),
        },
    }


@router.put("/config")
async def update_probe_config(req: ProbeConfigUpdate):
    """Update probe configuration (stored in reference_data)."""
    store = get_store()

    existing = await store.find_one(REFERENCE_DATA, {"ref_type": "probe_config"})
    update_data: dict[str, Any] = {"ref_type": "probe_config"}

    if existing:
        update_data = {**existing, **{k: v for k, v in req.dict().items() if v is not None}}
    else:
        update_data["_id"] = "probe-config-001"
        for k, v in req.dict().items():
            if v is not None:
                update_data[k] = v

    if existing:
        await store.update_one(
            REFERENCE_DATA,
            {"ref_type": "probe_config"},
            {"$set": update_data},
        )
    else:
        await store.insert_one(REFERENCE_DATA, update_data)

    return {"status": "updated", "config": update_data}


@router.get("/methods")
async def list_probe_methods():
    """List all available probe methods with descriptions."""
    return {
        "methods": [
            {
                "id": "tcp_socket",
                "name": "TCP Socket Probe",
                "description": "SYN probe — tests if TCP port is reachable. No login needed.",
                "protocol": "tcp",
                "agentless": True,
            },
            {
                "id": "icmp_ping",
                "name": "ICMP Ping",
                "description": "Echo request — tests host reachability. No port needed.",
                "protocol": "icmp",
                "agentless": True,
            },
            {
                "id": "traceroute",
                "name": "Traceroute",
                "description": "Hop-by-hop path trace — shows where traffic is blocked.",
                "protocol": "icmp/udp",
                "agentless": True,
            },
            {
                "id": "http_probe",
                "name": "HTTP(S) Probe",
                "description": "HTTP HEAD request — best for web services (80, 443, 8443).",
                "protocol": "http/https",
                "agentless": True,
            },
            {
                "id": "dns_probe",
                "name": "DNS Probe",
                "description": "DNS query to port 53 — tests DNS service availability.",
                "protocol": "udp",
                "agentless": True,
            },
            {
                "id": "firewall_api",
                "name": "Firewall API Query",
                "description": "Queries firewall management API (Palo Alto/Checkpoint/Fortinet) to check policy without sending traffic. Most accurate method.",
                "protocol": "any",
                "agentless": True,
                "requires_config": True,
            },
            {
                "id": "ocp_api",
                "name": "OCP/K8s API Probe",
                "description": "Probes from inside a pod/namespace via K8s exec API (RBAC only, no SSH).",
                "protocol": "any",
                "agentless": True,
                "requires_config": True,
            },
        ]
    }


@router.post("/export")
async def export_validation_results(
    results: list[dict],
    format: str = Query("xlsx", pattern="^(xlsx|csv)$"),
):
    """Export validation results as XLSX or CSV."""
    from fastapi.responses import StreamingResponse

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Source", "Destination", "Ports", "Overall Verdict",
            "Policy Verdict", "Live Verdict", "Drift Detected", "Notes",
        ])
        for r in results:
            writer.writerow([
                r.get("source", {}).get("input", ""),
                r.get("destination", {}).get("input", ""),
                ", ".join(r.get("ports_checked", [])),
                r.get("overall_verdict", ""),
                r.get("policy_verdict", ""),
                r.get("live_verdict", ""),
                r.get("drift_detected", False),
                "; ".join(r.get("notes", [])),
            ])
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=validation_results.csv"},
        )
    else:
        # XLSX export using openpyxl
        try:
            from openpyxl import Workbook
            from openpyxl.styles import PatternFill, Font
        except ImportError:
            raise HTTPException(500, "openpyxl not installed for XLSX export")

        wb = Workbook()
        ws = wb.active
        ws.title = "Validation Results"

        # Header
        headers = [
            "Source", "Source Type", "Source IPs", "Source Groups",
            "Destination", "Dest Type", "Dest IPs", "Dest Groups",
            "Ports", "Overall Verdict", "Policy Verdict", "Live Verdict",
            "Drift", "Latency (ms)", "Notes",
        ]
        ws.append(headers)
        for cell in ws[1]:
            cell.font = Font(bold=True)

        # Color fills for verdicts
        fill_pass = PatternFill("solid", fgColor="C6EFCE")
        fill_fail = PatternFill("solid", fgColor="FFC7CE")
        fill_drift = PatternFill("solid", fgColor="FFEB9C")

        for r in results:
            src = r.get("source", {})
            dst = r.get("destination", {})
            row = [
                src.get("input", ""),
                src.get("type", ""),
                ", ".join(src.get("resolved_ips", [])[:5]),
                ", ".join(src.get("matched_groups", [])[:3]),
                dst.get("input", ""),
                dst.get("type", ""),
                ", ".join(dst.get("resolved_ips", [])[:5]),
                ", ".join(dst.get("matched_groups", [])[:3]),
                ", ".join(r.get("ports_checked", [])),
                r.get("overall_verdict", ""),
                r.get("policy_verdict", ""),
                r.get("live_verdict", ""),
                "YES" if r.get("drift_detected") else "NO",
                "",  # Latency from probes
                "; ".join(r.get("notes", [])),
            ]
            ws.append(row)

            # Color the verdict cell
            row_num = ws.max_row
            verdict = r.get("overall_verdict", "")
            if verdict == "PASS":
                ws.cell(row=row_num, column=10).fill = fill_pass
            elif verdict in ("FAIL", "UNKNOWN"):
                ws.cell(row=row_num, column=10).fill = fill_fail
            elif verdict == "DRIFT":
                ws.cell(row=row_num, column=10).fill = fill_drift

        # Auto-width columns
        for col in ws.columns:
            max_length = max(len(str(cell.value or "")) for cell in col)
            ws.column_dimensions[col[0].column_letter].width = min(max_length + 2, 40)

        buffer = io.BytesIO()
        wb.save(buffer)
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=validation_results.xlsx"},
        )


# ---- Helpers ----

async def _log_validation(
    action: str, source: str, destination: str, ports: list[str], result: str
) -> None:
    """Log validation action to audit trail."""
    store = get_store()
    await store.insert_one(AUDIT_TRAIL, {
        "_id": f"audit-val-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        "collection": "validation",
        "action": action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "source": source,
            "destination": destination,
            "ports": ports,
            "result": result,
        },
    })
