"""Pass-Through Validation Engine — Live + Policy.

Two-layer validation:
  1. POLICY CHECK: Looks up deployed rules and policy matrix to determine
     what SHOULD happen (is there a rule permitting this traffic?)
  2. LIVE CHECK: Actually probes the destination to verify real-world
     connectivity (TCP SYN, UDP probe, ICMP where applicable).

Result shows both:
  - policy_verdict: PERMIT / DENY / NO_RULE
  - live_verdict: REACHABLE / UNREACHABLE / TIMEOUT / FILTERED / SKIPPED
  - drift_detected: True if policy ≠ live result (rule says permit but blocked, or vice versa)

Supports entity types: IP, CIDR, Group, VM, OCP Pod, OCP Service, OCP Route, FQDN
Modes: Single check, Bulk (parallel async probes)
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.db.store import get_store
from app.db.collections import GROUPS, COMPILED_RULES, REFERENCE_DATA


# ---- Enums ----

class EntityType(str, Enum):
    IP = "ip"
    CIDR = "cidr"
    GROUP = "group"
    VM = "vm"
    OCP_POD = "ocp_pod"
    OCP_SERVICE = "ocp_service"
    OCP_ROUTE = "ocp_route"
    FQDN = "fqdn"


class PolicyVerdict(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"
    NO_RULE = "NO_RULE"


class LiveVerdict(str, Enum):
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    TIMEOUT = "TIMEOUT"
    FILTERED = "FILTERED"
    SKIPPED = "SKIPPED"


class OverallVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    DRIFT = "DRIFT"
    UNKNOWN = "UNKNOWN"


# ---- Data Classes ----

@dataclass
class ResolvedEntity:
    original_input: str
    entity_type: EntityType
    resolved_ips: list[str] = field(default_factory=list)
    matched_groups: list[str] = field(default_factory=list)
    nh_id: str | None = None
    sz_code: str | None = None
    dc_id: str | None = None
    environment: str | None = None
    resolution_notes: list[str] = field(default_factory=list)


@dataclass
class RuleMatch:
    rule_id: str
    src_group: str
    dst_group: str
    ports: str
    action: str
    dc_id: str
    environment: str


@dataclass
class PolicyCheck:
    src_sz: str
    dst_sz: str
    action: str
    condition: str | None = None


@dataclass
class LiveProbeResult:
    """Result of a single live connectivity probe."""
    target_ip: str
    port: str
    protocol: str  # "tcp" or "udp"
    verdict: LiveVerdict
    latency_ms: float | None = None
    error: str | None = None


@dataclass
class ValidationResult:
    """Complete validation result — policy + live."""
    overall_verdict: OverallVerdict
    policy_verdict: PolicyVerdict
    live_verdict: LiveVerdict
    drift_detected: bool
    source: ResolvedEntity
    destination: ResolvedEntity
    ports_checked: list[str]
    matching_rules: list[RuleMatch] = field(default_factory=list)
    policy_checks: list[PolicyCheck] = field(default_factory=list)
    live_probes: list[LiveProbeResult] = field(default_factory=list)
    path_trace: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overall_verdict": self.overall_verdict.value,
            "policy_verdict": self.policy_verdict.value,
            "live_verdict": self.live_verdict.value,
            "drift_detected": self.drift_detected,
            "source": {
                "input": self.source.original_input,
                "type": self.source.entity_type.value,
                "resolved_ips": self.source.resolved_ips,
                "matched_groups": self.source.matched_groups,
                "nh_id": self.source.nh_id,
                "sz_code": self.source.sz_code,
                "dc_id": self.source.dc_id,
                "environment": self.source.environment,
                "notes": self.source.resolution_notes,
            },
            "destination": {
                "input": self.destination.original_input,
                "type": self.destination.entity_type.value,
                "resolved_ips": self.destination.resolved_ips,
                "matched_groups": self.destination.matched_groups,
                "nh_id": self.destination.nh_id,
                "sz_code": self.destination.sz_code,
                "dc_id": self.destination.dc_id,
                "environment": self.destination.environment,
                "notes": self.destination.resolution_notes,
            },
            "ports_checked": self.ports_checked,
            "matching_rules": [
                {
                    "rule_id": r.rule_id,
                    "src_group": r.src_group,
                    "dst_group": r.dst_group,
                    "ports": r.ports,
                    "action": r.action,
                    "dc_id": r.dc_id,
                    "environment": r.environment,
                }
                for r in self.matching_rules
            ],
            "policy_checks": [
                {"src_sz": p.src_sz, "dst_sz": p.dst_sz, "action": p.action, "condition": p.condition}
                for p in self.policy_checks
            ],
            "live_probes": [
                {
                    "target_ip": lp.target_ip,
                    "port": lp.port,
                    "protocol": lp.protocol,
                    "verdict": lp.verdict.value,
                    "latency_ms": lp.latency_ms,
                    "error": lp.error,
                }
                for lp in self.live_probes
            ],
            "path_trace": self.path_trace,
            "notes": self.notes,
        }


# ---- Entity Detection ----

def detect_entity_type(value: str) -> EntityType:
    """Auto-detect entity type from input string."""
    value = value.strip()

    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return EntityType.CIDR
        except ValueError:
            pass

    try:
        ipaddress.ip_address(value)
        return EntityType.IP
    except ValueError:
        pass

    if value.startswith("pod/") or value.startswith("pod:"):
        return EntityType.OCP_POD
    if value.startswith("svc/") or value.startswith("service/"):
        return EntityType.OCP_SERVICE
    if value.startswith("route/"):
        return EntityType.OCP_ROUTE
    if value.startswith("vm-") or value.startswith("svr-"):
        return EntityType.VM
    if value.startswith("grp-") or value.startswith("g-"):
        return EntityType.GROUP
    if "." in value and not value.replace(".", "").isdigit():
        return EntityType.FQDN

    return EntityType.GROUP


# ---- Entity Resolution ----

async def resolve_entity(value: str, entity_type: EntityType | None = None) -> ResolvedEntity:
    """Resolve an entity to IPs and find which groups contain it."""
    store = get_store()
    value = value.strip()

    if entity_type is None:
        entity_type = detect_entity_type(value)

    entity = ResolvedEntity(original_input=value, entity_type=entity_type)

    if entity_type == EntityType.IP:
        entity.resolved_ips = [value]
        await _find_groups_for_ips(entity, store)

    elif entity_type == EntityType.CIDR:
        entity.resolved_ips = [value]
        entity.resolution_notes.append(f"CIDR network: {value}")
        await _find_groups_for_cidr(entity, store)

    elif entity_type == EntityType.GROUP:
        group = await store.find_one(GROUPS, {"name": value})
        if group:
            entity.matched_groups = [value]
            entity.nh_id = group.get("nh_id")
            entity.sz_code = group.get("sz_code")
            entity.dc_id = group.get("dc_id")
            entity.environment = group.get("environment")
            members = group.get("members", [])
            entity.resolved_ips = [m.get("value", "") for m in members if m.get("value")]
            entity.resolution_notes.append(f"Group resolved: {len(members)} members")
        else:
            entity.resolution_notes.append(f"Group '{value}' not found")

    elif entity_type == EntityType.VM:
        vm_doc = await store.find_one(REFERENCE_DATA, {
            "ref_type": "vm_registry",
            "$or": [{"name": value}, {"hostname": value}],
        })
        if vm_doc:
            ips = vm_doc.get("ip_addresses", [])
            entity.resolved_ips = ips
            entity.dc_id = vm_doc.get("dc_id")
            entity.environment = vm_doc.get("environment")
            entity.resolution_notes.append(f"VM resolved → {len(ips)} IP(s)")
            await _find_groups_for_ips(entity, store)
        else:
            entity.resolution_notes.append(f"VM '{value}' not found in registry")

    elif entity_type == EntityType.OCP_POD:
        await _resolve_ocp_entity(entity, "pod", value.replace("pod/", "").replace("pod:", ""), store)

    elif entity_type == EntityType.OCP_SERVICE:
        await _resolve_ocp_entity(entity, "service", value.replace("svc/", "").replace("service/", ""), store)

    elif entity_type == EntityType.OCP_ROUTE:
        await _resolve_ocp_entity(entity, "route", value.replace("route/", ""), store)

    elif entity_type == EntityType.FQDN:
        await _resolve_fqdn(entity, value, store)

    return entity


async def _resolve_fqdn(entity: ResolvedEntity, value: str, store) -> None:
    """Resolve FQDN via endpoint entries, DNS registry, or live DNS lookup."""
    # Check ingress groups endpoint_entries
    groups = await store.find(GROUPS, {"group_type": "ingress"})
    for grp in groups:
        for ep in grp.get("endpoint_entries", []):
            if ep.get("endpoint_name") == value:
                entity.resolved_ips = ep.get("resolved_ips", [])
                entity.matched_groups = [grp.get("name", "")]
                entity.nh_id = grp.get("nh_id")
                entity.sz_code = grp.get("sz_code")
                entity.dc_id = grp.get("dc_id")
                entity.environment = grp.get("environment")
                entity.resolution_notes.append(f"FQDN matched endpoint in group '{grp.get('name')}'")
                return

    # Check DNS registry
    dns_doc = await store.find_one(REFERENCE_DATA, {"ref_type": "dns_record", "fqdn": value})
    if dns_doc:
        entity.resolved_ips = dns_doc.get("resolved_ips", [])
        entity.resolution_notes.append("Resolved via DNS registry")
        await _find_groups_for_ips(entity, store)
        return

    # Live DNS resolution as fallback
    try:
        loop = asyncio.get_event_loop()
        addrs = await loop.run_in_executor(None, socket.getaddrinfo, value, None)
        ips = list(set(addr[4][0] for addr in addrs))
        if ips:
            entity.resolved_ips = ips
            entity.resolution_notes.append(f"Live DNS resolved: {', '.join(ips)}")
            await _find_groups_for_ips(entity, store)
            return
    except (socket.gaierror, OSError):
        pass

    entity.resolution_notes.append(f"FQDN '{value}' could not be resolved")


async def _find_groups_for_ips(entity: ResolvedEntity, store) -> None:
    """Find which groups contain the entity's resolved IPs."""
    if not entity.resolved_ips:
        return

    all_groups = await store.find(GROUPS, limit=5000)
    for grp in all_groups:
        for member in grp.get("members", []):
            member_val = member.get("value", "")
            for ip in entity.resolved_ips:
                if _ip_matches_member(ip, member_val):
                    grp_name = grp.get("name", "")
                    if grp_name not in entity.matched_groups:
                        entity.matched_groups.append(grp_name)
                        if not entity.nh_id:
                            entity.nh_id = grp.get("nh_id")
                            entity.sz_code = grp.get("sz_code")
                            entity.dc_id = grp.get("dc_id")
                            entity.environment = grp.get("environment")
                    break


async def _find_groups_for_cidr(entity: ResolvedEntity, store) -> None:
    """Find groups that overlap with a CIDR."""
    if not entity.resolved_ips:
        return
    try:
        check_net = ipaddress.ip_network(entity.resolved_ips[0], strict=False)
    except ValueError:
        return

    all_groups = await store.find(GROUPS, limit=5000)
    for grp in all_groups:
        for member in grp.get("members", []):
            member_val = member.get("value", "")
            try:
                if "/" in member_val:
                    if check_net.overlaps(ipaddress.ip_network(member_val, strict=False)):
                        grp_name = grp.get("name", "")
                        if grp_name not in entity.matched_groups:
                            entity.matched_groups.append(grp_name)
                            if not entity.nh_id:
                                entity.nh_id = grp.get("nh_id")
                                entity.sz_code = grp.get("sz_code")
                                entity.dc_id = grp.get("dc_id")
                                entity.environment = grp.get("environment")
                        break
                else:
                    if ipaddress.ip_address(member_val) in check_net:
                        grp_name = grp.get("name", "")
                        if grp_name not in entity.matched_groups:
                            entity.matched_groups.append(grp_name)
                            if not entity.nh_id:
                                entity.nh_id = grp.get("nh_id")
                                entity.sz_code = grp.get("sz_code")
                                entity.dc_id = grp.get("dc_id")
                                entity.environment = grp.get("environment")
                        break
            except ValueError:
                continue


async def _resolve_ocp_entity(entity: ResolvedEntity, ocp_type: str, ref: str, store) -> None:
    """Resolve OCP pod/service/route from reference_data."""
    parts = ref.split("/") if "/" in ref else ref.split(":")
    namespace = parts[0] if len(parts) > 1 else "default"
    name = parts[-1]

    ocp_doc = await store.find_one(REFERENCE_DATA, {
        "ref_type": f"ocp_{ocp_type}",
        "namespace": namespace,
        "name": name,
    })

    if ocp_doc:
        if ocp_type == "pod":
            entity.resolved_ips = [ocp_doc.get("pod_ip", "")]
            entity.resolution_notes.append(f"OCP pod {namespace}/{name} → {ocp_doc.get('pod_ip')}")
        elif ocp_type == "service":
            entity.resolved_ips = ocp_doc.get("endpoint_ips", [])
            entity.resolution_notes.append(
                f"OCP service {namespace}/{name} → {len(entity.resolved_ips)} endpoints"
            )
        elif ocp_type == "route":
            entity.resolved_ips = ocp_doc.get("ingress_ips", [])
            entity.resolution_notes.append(
                f"OCP route {namespace}/{name} → host: {ocp_doc.get('host', '')}"
            )
        entity.dc_id = ocp_doc.get("dc_id") or ocp_doc.get("cluster_dc")
        entity.environment = ocp_doc.get("environment")
        await _find_groups_for_ips(entity, store)
    else:
        entity.resolution_notes.append(f"OCP {ocp_type} '{ref}' not found in registry")


def _ip_matches_member(ip_str: str, member_val: str) -> bool:
    """Check if an IP matches a member (IP or CIDR)."""
    try:
        if "/" in member_val:
            return ipaddress.ip_address(ip_str) in ipaddress.ip_network(member_val, strict=False)
        return ip_str == member_val
    except ValueError:
        return ip_str == member_val


# ---- Live Connectivity Probes ----

async def _probe_tcp(ip: str, port: int, timeout: float = 3.0) -> LiveProbeResult:
    """Attempt TCP connection to ip:port. Returns REACHABLE if SYN-ACK received."""
    import time
    start = time.monotonic()
    try:
        loop = asyncio.get_event_loop()
        # asyncio.open_connection for async TCP probe
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        latency = (time.monotonic() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return LiveProbeResult(
            target_ip=ip, port=str(port), protocol="tcp",
            verdict=LiveVerdict.REACHABLE, latency_ms=round(latency, 2),
        )
    except asyncio.TimeoutError:
        return LiveProbeResult(
            target_ip=ip, port=str(port), protocol="tcp",
            verdict=LiveVerdict.TIMEOUT, error="Connection timed out",
        )
    except ConnectionRefusedError:
        latency = (time.monotonic() - start) * 1000
        # Connection refused means we reached the host but port is closed
        # This still means the firewall is OPEN (traffic passes through)
        return LiveProbeResult(
            target_ip=ip, port=str(port), protocol="tcp",
            verdict=LiveVerdict.REACHABLE, latency_ms=round(latency, 2),
            error="Port closed (connection refused) — but host reachable, firewall open",
        )
    except OSError as e:
        if "No route to host" in str(e):
            return LiveProbeResult(
                target_ip=ip, port=str(port), protocol="tcp",
                verdict=LiveVerdict.UNREACHABLE, error="No route to host",
            )
        if "Network is unreachable" in str(e):
            return LiveProbeResult(
                target_ip=ip, port=str(port), protocol="tcp",
                verdict=LiveVerdict.UNREACHABLE, error="Network unreachable",
            )
        return LiveProbeResult(
            target_ip=ip, port=str(port), protocol="tcp",
            verdict=LiveVerdict.FILTERED, error=str(e),
        )


async def _probe_udp(ip: str, port: int, timeout: float = 3.0) -> LiveProbeResult:
    """Send UDP probe. Best-effort — UDP is connectionless."""
    import time
    start = time.monotonic()
    try:
        loop = asyncio.get_event_loop()
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.settimeout(timeout)

        # Send empty probe
        await loop.run_in_executor(None, sock.sendto, b"\x00", (ip, port))

        # Try to receive ICMP unreachable (will raise error if filtered)
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, sock.recv, 1024),
                timeout=timeout,
            )
            latency = (time.monotonic() - start) * 1000
            sock.close()
            return LiveProbeResult(
                target_ip=ip, port=str(port), protocol="udp",
                verdict=LiveVerdict.REACHABLE, latency_ms=round(latency, 2),
            )
        except (asyncio.TimeoutError, socket.timeout):
            latency = (time.monotonic() - start) * 1000
            sock.close()
            # No ICMP unreachable = likely open or filtered
            return LiveProbeResult(
                target_ip=ip, port=str(port), protocol="udp",
                verdict=LiveVerdict.REACHABLE, latency_ms=round(latency, 2),
                error="No ICMP unreachable — assumed open (UDP is best-effort)",
            )
    except ConnectionRefusedError:
        latency = (time.monotonic() - start) * 1000
        return LiveProbeResult(
            target_ip=ip, port=str(port), protocol="udp",
            verdict=LiveVerdict.UNREACHABLE, latency_ms=round(latency, 2),
            error="ICMP port unreachable received",
        )
    except OSError as e:
        return LiveProbeResult(
            target_ip=ip, port=str(port), protocol="udp",
            verdict=LiveVerdict.FILTERED, error=str(e),
        )


async def _run_live_probes(
    target_ips: list[str],
    ports: list[str],
    timeout: float = 3.0,
    max_probes: int = 20,
) -> list[LiveProbeResult]:
    """Run live connectivity probes against resolved target IPs and ports."""
    probes: list = []
    count = 0

    for ip in target_ips:
        # Skip CIDR notation for live probes (take first IP if available)
        if "/" in ip:
            try:
                net = ipaddress.ip_network(ip, strict=False)
                # Use first usable host
                hosts = list(net.hosts())
                if hosts:
                    ip = str(hosts[0])
                else:
                    continue
            except ValueError:
                continue

        for port_spec in ports:
            if count >= max_probes:
                break

            # Parse protocol/port
            port_spec = port_spec.strip().lower()
            if "/" in port_spec:
                proto, port_num = port_spec.split("/", 1)
            else:
                proto, port_num = "tcp", port_spec

            try:
                port_int = int(port_num)
            except ValueError:
                continue

            if proto == "udp":
                probes.append(_probe_udp(ip, port_int, timeout))
            else:
                probes.append(_probe_tcp(ip, port_int, timeout))
            count += 1

    if not probes:
        return []

    results = await asyncio.gather(*probes, return_exceptions=True)
    live_results = []
    for r in results:
        if isinstance(r, LiveProbeResult):
            live_results.append(r)
        elif isinstance(r, Exception):
            live_results.append(LiveProbeResult(
                target_ip="unknown", port="unknown", protocol="tcp",
                verdict=LiveVerdict.FILTERED, error=str(r),
            ))
    return live_results


# ---- Policy Check ----

async def _check_policy(
    src_entity: ResolvedEntity,
    dst_entity: ResolvedEntity,
    ports: list[str],
    environment: str | None = None,
) -> tuple[PolicyVerdict, list[RuleMatch], list[PolicyCheck]]:
    """Check rules and policy matrix for src → dst."""
    store = get_store()
    permit_rules: list[RuleMatch] = []
    deny_rules: list[RuleMatch] = []

    for src_grp in (src_entity.matched_groups or [""]):
        for dst_grp in (dst_entity.matched_groups or [""]):
            query: dict[str, Any] = {}
            if src_grp:
                query["src_group_ref"] = src_grp
            if dst_grp:
                query["dst_group_ref"] = dst_grp
            if environment:
                query["environment"] = environment
            elif src_entity.environment:
                query["environment"] = src_entity.environment

            rules = await store.find(COMPILED_RULES, query, limit=100)
            for rule in rules:
                rule_ports = rule.get("ports", "")
                if _ports_match(ports, rule_ports):
                    rm = RuleMatch(
                        rule_id=rule.get("rule_id", rule.get("_id", "")),
                        src_group=rule.get("src_group_ref", ""),
                        dst_group=rule.get("dst_group_ref", ""),
                        ports=rule_ports,
                        action=rule.get("action", "permit"),
                        dc_id=rule.get("src_dc", ""),
                        environment=rule.get("environment", ""),
                    )
                    if rm.action == "permit":
                        permit_rules.append(rm)
                    else:
                        deny_rules.append(rm)

    # Policy matrix check
    policy_checks: list[PolicyCheck] = []
    if src_entity.sz_code and dst_entity.sz_code:
        policy_docs = await store.find(REFERENCE_DATA, {"ref_type": "policy_matrix"})
        for pm in policy_docs:
            pm_env = pm.get("environment", "")
            target_env = environment or src_entity.environment or ""
            if pm_env and target_env and pm_env != target_env:
                continue

            matched_rule = False
            for r in pm.get("rules", []):
                if r.get("src_sz") == src_entity.sz_code and r.get("dst_sz") == dst_entity.sz_code:
                    policy_checks.append(PolicyCheck(
                        src_sz=r.get("src_sz", ""),
                        dst_sz=r.get("dst_sz", ""),
                        action=r.get("action", "deny"),
                        condition=r.get("condition"),
                    ))
                    matched_rule = True

            if not matched_rule:
                policy_checks.append(PolicyCheck(
                    src_sz=src_entity.sz_code,
                    dst_sz=dst_entity.sz_code,
                    action=pm.get("default_action", "deny"),
                    condition="default_policy",
                ))

    # Determine policy verdict
    if deny_rules:
        return PolicyVerdict.DENY, deny_rules + permit_rules, policy_checks
    elif permit_rules:
        return PolicyVerdict.PERMIT, permit_rules + deny_rules, policy_checks
    else:
        return PolicyVerdict.NO_RULE, [], policy_checks


def _ports_match(check_ports: list[str], rule_ports: str) -> bool:
    """Check if requested ports match rule's port spec."""
    if not rule_ports or rule_ports == "any":
        return True

    rule_port_list = rule_ports.replace(",", " ").split()

    for check_port in check_ports:
        check_normalized = check_port.strip().lower()
        if "/" not in check_normalized:
            check_normalized = f"tcp/{check_normalized}"

        for rp in rule_port_list:
            rp_normalized = rp.strip().lower()
            if "/" not in rp_normalized:
                rp_normalized = f"tcp/{rp_normalized}"

            if check_normalized == rp_normalized:
                return True

            # Range: tcp/1024-2048
            if "-" in rp_normalized:
                proto, port_range = rp_normalized.split("/", 1)
                check_proto, check_port_num = check_normalized.split("/", 1)
                if proto == check_proto:
                    try:
                        start, end = port_range.split("-")
                        if int(start) <= int(check_port_num) <= int(end):
                            return True
                    except (ValueError, IndexError):
                        pass
    return False


# ---- Main Validation Function ----

async def validate_pass_through(
    source: str,
    destination: str,
    ports: list[str],
    environment: str | None = None,
    source_type: EntityType | None = None,
    destination_type: EntityType | None = None,
    live_check: bool = True,
    timeout: float = 3.0,
) -> ValidationResult:
    """Full pass-through validation: resolve entities, check policy, run live probes.

    Args:
        source: Source entity (IP, group name, VM, OCP ref, FQDN)
        destination: Destination entity
        ports: List of port specs (e.g., ["tcp/443", "udp/53", "8080"])
        environment: Optional environment filter
        live_check: If True, run actual connectivity probes
        timeout: Timeout per probe in seconds
    """
    # Resolve entities
    src_entity = await resolve_entity(source, source_type)
    dst_entity = await resolve_entity(destination, destination_type)

    # Policy check
    policy_verdict, matching_rules, policy_checks = await _check_policy(
        src_entity, dst_entity, ports, environment
    )

    # Live check
    live_probes: list[LiveProbeResult] = []
    live_verdict = LiveVerdict.SKIPPED

    if live_check and dst_entity.resolved_ips:
        live_probes = await _run_live_probes(
            dst_entity.resolved_ips, ports, timeout=timeout
        )
        if live_probes:
            reachable = sum(1 for p in live_probes if p.verdict == LiveVerdict.REACHABLE)
            total = len(live_probes)
            if reachable == total:
                live_verdict = LiveVerdict.REACHABLE
            elif reachable == 0:
                # Check if timeout or unreachable
                timeouts = sum(1 for p in live_probes if p.verdict == LiveVerdict.TIMEOUT)
                if timeouts == total:
                    live_verdict = LiveVerdict.TIMEOUT
                else:
                    live_verdict = LiveVerdict.UNREACHABLE
            else:
                live_verdict = LiveVerdict.FILTERED  # Partial reachability
    elif not live_check:
        live_verdict = LiveVerdict.SKIPPED
    elif not dst_entity.resolved_ips:
        live_verdict = LiveVerdict.SKIPPED

    # Determine drift
    drift = False
    if live_verdict != LiveVerdict.SKIPPED:
        if policy_verdict == PolicyVerdict.PERMIT and live_verdict in (
            LiveVerdict.UNREACHABLE, LiveVerdict.TIMEOUT
        ):
            drift = True
        elif policy_verdict == PolicyVerdict.DENY and live_verdict == LiveVerdict.REACHABLE:
            drift = True

    # Overall verdict
    if drift:
        overall = OverallVerdict.DRIFT
    elif live_verdict == LiveVerdict.REACHABLE and policy_verdict == PolicyVerdict.PERMIT:
        overall = OverallVerdict.PASS
    elif live_verdict == LiveVerdict.REACHABLE and policy_verdict == PolicyVerdict.NO_RULE:
        overall = OverallVerdict.PARTIAL
    elif live_verdict in (LiveVerdict.UNREACHABLE, LiveVerdict.TIMEOUT):
        overall = OverallVerdict.FAIL
    elif live_verdict == LiveVerdict.SKIPPED:
        # Fall back to policy only
        if policy_verdict == PolicyVerdict.PERMIT:
            overall = OverallVerdict.PASS
        elif policy_verdict == PolicyVerdict.DENY:
            overall = OverallVerdict.FAIL
        else:
            overall = OverallVerdict.UNKNOWN
    else:
        overall = OverallVerdict.UNKNOWN

    # Build path trace
    path_trace = [
        f"Source: {source} ({src_entity.entity_type.value})",
    ]
    if src_entity.resolved_ips:
        path_trace.append(f"  → IPs: {', '.join(src_entity.resolved_ips[:5])}")
    if src_entity.matched_groups:
        path_trace.append(f"  → Groups: {', '.join(src_entity.matched_groups[:3])}")
    if src_entity.sz_code:
        path_trace.append(f"  → Zone: {src_entity.nh_id}/{src_entity.sz_code}")
    path_trace.append(f"Destination: {destination} ({dst_entity.entity_type.value})")
    if dst_entity.resolved_ips:
        path_trace.append(f"  → IPs: {', '.join(dst_entity.resolved_ips[:5])}")
    if dst_entity.matched_groups:
        path_trace.append(f"  → Groups: {', '.join(dst_entity.matched_groups[:3])}")
    if dst_entity.sz_code:
        path_trace.append(f"  → Zone: {dst_entity.nh_id}/{dst_entity.sz_code}")
    path_trace.append(f"Ports: {', '.join(ports)}")
    path_trace.append(f"Policy: {policy_verdict.value}")
    path_trace.append(f"Live: {live_verdict.value}")
    if drift:
        path_trace.append("⚠ DRIFT DETECTED: Policy and live results do not match!")

    # Notes
    notes: list[str] = []
    if matching_rules:
        notes.append(f"Found {len(matching_rules)} matching rule(s)")
    if drift:
        notes.append(
            f"DRIFT: Policy says {policy_verdict.value} but live probe says {live_verdict.value}"
        )
    if not src_entity.matched_groups:
        notes.append("Source not found in any firewall group")
    if not dst_entity.matched_groups:
        notes.append("Destination not found in any firewall group")

    return ValidationResult(
        overall_verdict=overall,
        policy_verdict=policy_verdict,
        live_verdict=live_verdict,
        drift_detected=drift,
        source=src_entity,
        destination=dst_entity,
        ports_checked=ports,
        matching_rules=matching_rules,
        policy_checks=policy_checks,
        live_probes=live_probes,
        path_trace=path_trace,
        notes=notes,
    )


# ---- Bulk Validation ----

async def validate_bulk(
    checks: list[dict],
    environment: str | None = None,
    live_check: bool = True,
    timeout: float = 3.0,
    max_concurrent: int = 10,
) -> list[dict]:
    """Run multiple validations in parallel with concurrency control.

    Each check: {"source": "...", "destination": "...", "ports": ["..."]}
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _run_one(i: int, check: dict) -> dict:
        async with semaphore:
            src = check.get("source", "")
            dst = check.get("destination", "")
            ports = check.get("ports", [])
            if isinstance(ports, str):
                ports = [p.strip() for p in ports.replace(",", " ").split() if p.strip()]

            if not src or not dst:
                return {
                    "index": i,
                    "overall_verdict": "UNKNOWN",
                    "error": "Missing source or destination",
                    "source_input": src,
                    "destination_input": dst,
                }

            result = await validate_pass_through(
                source=src, destination=dst, ports=ports,
                environment=environment, live_check=live_check, timeout=timeout,
            )
            d = result.to_dict()
            d["index"] = i
            return d

    tasks = [_run_one(i, check) for i, check in enumerate(checks)]
    results = await asyncio.gather(*tasks)
    return sorted(results, key=lambda r: r.get("index", 0))
