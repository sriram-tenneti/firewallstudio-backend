"""Multi-method agentless connectivity probe engine.

All methods are agentless — no login or software installation required on
source/destination systems.

Probe methods (in recommended fallback order):
  1. tcp_socket   — TCP SYN probe (no login, just network access)
  2. icmp_ping    — ICMP echo request (host reachability)
  3. traceroute   — Hop-by-hop path trace (shows where traffic is blocked)
  4. http_probe   — HTTP HEAD request (for web services on 80/443/8443)
  5. dns_probe    — DNS query to port 53
  6. firewall_api — Query firewall appliance API (Palo Alto, Checkpoint, Fortinet)
                    Asks "would this traffic be allowed?" without sending actual traffic
  7. ocp_api      — Query K8s/OCP API to probe from inside a namespace (RBAC only)

Configuration is per-org via reference_data (ref_type: "probe_config").
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx


class ProbeMethod(str, Enum):
    TCP_SOCKET = "tcp_socket"
    ICMP_PING = "icmp_ping"
    TRACEROUTE = "traceroute"
    HTTP_PROBE = "http_probe"
    DNS_PROBE = "dns_probe"
    FIREWALL_API = "firewall_api"
    OCP_API = "ocp_api"


class ProbeVerdict(str, Enum):
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    TIMEOUT = "TIMEOUT"
    FILTERED = "FILTERED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass
class ProbeResult:
    """Result of a single probe attempt."""
    method: ProbeMethod
    target_ip: str
    port: str
    protocol: str
    verdict: ProbeVerdict
    latency_ms: float | None = None
    hops: list[dict] | None = None  # For traceroute
    details: str | None = None
    error: str | None = None


@dataclass
class ProbeConfig:
    """Organization-level probe configuration."""
    enabled_methods: list[ProbeMethod] = field(default_factory=lambda: [
        ProbeMethod.TCP_SOCKET,
        ProbeMethod.ICMP_PING,
        ProbeMethod.HTTP_PROBE,
    ])
    fallback_order: list[ProbeMethod] = field(default_factory=lambda: [
        ProbeMethod.TCP_SOCKET,
        ProbeMethod.HTTP_PROBE,
        ProbeMethod.ICMP_PING,
        ProbeMethod.TRACEROUTE,
        ProbeMethod.FIREWALL_API,
    ])
    disabled_methods: list[ProbeMethod] = field(default_factory=list)
    timeout_seconds: float = 5.0
    max_concurrent_probes: int = 20
    # Firewall API config
    firewall_provider: str | None = None  # "palo_alto", "checkpoint", "fortinet"
    firewall_api_url: str | None = None
    firewall_api_key_env: str | None = None  # env var name, e.g. "$FIREWALL_API_KEY"
    # OCP/K8s config
    ocp_api_url: str | None = None
    ocp_token_env: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "ProbeConfig":
        cfg = cls()
        if "enabled_methods" in data:
            cfg.enabled_methods = [ProbeMethod(m) for m in data["enabled_methods"]]
        if "fallback_order" in data:
            cfg.fallback_order = [ProbeMethod(m) for m in data["fallback_order"]]
        if "disabled_methods" in data:
            cfg.disabled_methods = [ProbeMethod(m) for m in data["disabled_methods"]]
        if "timeout_seconds" in data:
            cfg.timeout_seconds = float(data["timeout_seconds"])
        if "max_concurrent_probes" in data:
            cfg.max_concurrent_probes = int(data["max_concurrent_probes"])
        if "firewall_api" in data:
            fa = data["firewall_api"]
            cfg.firewall_provider = fa.get("provider")
            cfg.firewall_api_url = fa.get("base_url")
            cfg.firewall_api_key_env = fa.get("api_key_ref")
        if "ocp_api" in data:
            oa = data["ocp_api"]
            cfg.ocp_api_url = oa.get("base_url")
            cfg.ocp_token_env = oa.get("token_ref")
        return cfg


async def load_probe_config() -> ProbeConfig:
    """Load probe configuration from reference_data store."""
    from app.db.store import get_store
    from app.db.collections import REFERENCE_DATA

    store = get_store()
    doc = await store.find_one(REFERENCE_DATA, {"ref_type": "probe_config"})
    if doc:
        return ProbeConfig.from_dict(doc)
    return ProbeConfig()


# ---- Individual Probe Methods ----

async def probe_tcp_socket(ip: str, port: int, timeout: float = 5.0) -> ProbeResult:
    """TCP SYN probe — most common, works without any login."""
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        latency = (time.monotonic() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return ProbeResult(
            method=ProbeMethod.TCP_SOCKET, target_ip=ip, port=str(port),
            protocol="tcp", verdict=ProbeVerdict.REACHABLE,
            latency_ms=round(latency, 2),
            details="TCP connection established (SYN-ACK received)",
        )
    except asyncio.TimeoutError:
        return ProbeResult(
            method=ProbeMethod.TCP_SOCKET, target_ip=ip, port=str(port),
            protocol="tcp", verdict=ProbeVerdict.TIMEOUT,
            latency_ms=round((time.monotonic() - start) * 1000, 2),
            details="No SYN-ACK — connection timed out (likely filtered by firewall)",
        )
    except ConnectionRefusedError:
        latency = (time.monotonic() - start) * 1000
        return ProbeResult(
            method=ProbeMethod.TCP_SOCKET, target_ip=ip, port=str(port),
            protocol="tcp", verdict=ProbeVerdict.REACHABLE,
            latency_ms=round(latency, 2),
            details="RST received — port closed but host reachable (firewall OPEN)",
        )
    except OSError as e:
        verdict = ProbeVerdict.UNREACHABLE
        if "No route" in str(e) or "Network is unreachable" in str(e):
            verdict = ProbeVerdict.UNREACHABLE
        else:
            verdict = ProbeVerdict.FILTERED
        return ProbeResult(
            method=ProbeMethod.TCP_SOCKET, target_ip=ip, port=str(port),
            protocol="tcp", verdict=verdict, error=str(e),
        )


async def probe_icmp_ping(ip: str, timeout: float = 5.0) -> ProbeResult:
    """ICMP echo — checks host reachability without needing any port."""
    start = time.monotonic()
    try:
        # Use system ping (works without root on most systems)
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", str(int(timeout)), ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        latency = (time.monotonic() - start) * 1000

        if proc.returncode == 0:
            # Parse latency from ping output
            output = stdout.decode()
            ping_latency = latency
            if "time=" in output:
                try:
                    time_part = output.split("time=")[-1].split()[0]
                    ping_latency = float(time_part.replace("ms", ""))
                except (ValueError, IndexError):
                    pass
            return ProbeResult(
                method=ProbeMethod.ICMP_PING, target_ip=ip, port="icmp",
                protocol="icmp", verdict=ProbeVerdict.REACHABLE,
                latency_ms=round(ping_latency, 2),
                details="ICMP echo reply received — host is reachable",
            )
        else:
            return ProbeResult(
                method=ProbeMethod.ICMP_PING, target_ip=ip, port="icmp",
                protocol="icmp", verdict=ProbeVerdict.UNREACHABLE,
                latency_ms=round(latency, 2),
                details="No ICMP reply — host unreachable or ICMP blocked",
            )
    except asyncio.TimeoutError:
        return ProbeResult(
            method=ProbeMethod.ICMP_PING, target_ip=ip, port="icmp",
            protocol="icmp", verdict=ProbeVerdict.TIMEOUT,
            details="ICMP ping timed out",
        )
    except Exception as e:
        return ProbeResult(
            method=ProbeMethod.ICMP_PING, target_ip=ip, port="icmp",
            protocol="icmp", verdict=ProbeVerdict.ERROR, error=str(e),
        )


async def probe_traceroute(ip: str, timeout: float = 10.0) -> ProbeResult:
    """Traceroute — shows hop-by-hop path, reveals where traffic is blocked."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "traceroute", "-n", "-m", "15", "-w", "2", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        output = stdout.decode()

        hops: list[dict] = []
        reached = False
        for line in output.strip().split("\n")[1:]:  # Skip header
            parts = line.strip().split()
            if len(parts) >= 2:
                hop_num = parts[0]
                hop_ip = parts[1] if parts[1] != "*" else None
                hop_latency = None
                if len(parts) >= 3 and parts[2] != "*":
                    try:
                        hop_latency = float(parts[2].replace("ms", ""))
                    except ValueError:
                        pass
                hops.append({
                    "hop": int(hop_num) if hop_num.isdigit() else 0,
                    "ip": hop_ip,
                    "latency_ms": hop_latency,
                    "timeout": hop_ip is None,
                })
                if hop_ip == ip:
                    reached = True

        verdict = ProbeVerdict.REACHABLE if reached else ProbeVerdict.FILTERED
        last_hop = hops[-1] if hops else None
        details = f"Traced {len(hops)} hops"
        if reached:
            details += f" — reached destination at hop {len(hops)}"
        elif hops:
            # Find where it stops
            last_responding = next(
                (h for h in reversed(hops) if h.get("ip")), None
            )
            if last_responding:
                details += f" — last responding hop: {last_responding['ip']} (hop {last_responding['hop']})"
            else:
                details += " — all hops timed out (heavily filtered)"

        return ProbeResult(
            method=ProbeMethod.TRACEROUTE, target_ip=ip, port="*",
            protocol="icmp/udp", verdict=verdict,
            hops=hops, details=details,
        )
    except asyncio.TimeoutError:
        return ProbeResult(
            method=ProbeMethod.TRACEROUTE, target_ip=ip, port="*",
            protocol="icmp/udp", verdict=ProbeVerdict.TIMEOUT,
            details="Traceroute timed out",
        )
    except FileNotFoundError:
        return ProbeResult(
            method=ProbeMethod.TRACEROUTE, target_ip=ip, port="*",
            protocol="icmp/udp", verdict=ProbeVerdict.SKIPPED,
            details="traceroute not available on this system",
        )
    except Exception as e:
        return ProbeResult(
            method=ProbeMethod.TRACEROUTE, target_ip=ip, port="*",
            protocol="icmp/udp", verdict=ProbeVerdict.ERROR, error=str(e),
        )


async def probe_http(ip: str, port: int, timeout: float = 5.0) -> ProbeResult:
    """HTTP(S) HEAD request — best for web services."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    start = time.monotonic()

    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            resp = await client.head(url, follow_redirects=True)
            latency = (time.monotonic() - start) * 1000
            return ProbeResult(
                method=ProbeMethod.HTTP_PROBE, target_ip=ip, port=str(port),
                protocol="http", verdict=ProbeVerdict.REACHABLE,
                latency_ms=round(latency, 2),
                details=f"HTTP {resp.status_code} — service responding",
            )
    except httpx.ConnectTimeout:
        return ProbeResult(
            method=ProbeMethod.HTTP_PROBE, target_ip=ip, port=str(port),
            protocol="http", verdict=ProbeVerdict.TIMEOUT,
            details="HTTP connection timed out (likely filtered)",
        )
    except httpx.ConnectError as e:
        if "refused" in str(e).lower():
            return ProbeResult(
                method=ProbeMethod.HTTP_PROBE, target_ip=ip, port=str(port),
                protocol="http", verdict=ProbeVerdict.REACHABLE,
                details="Connection refused — host reachable but no HTTP service (firewall OPEN)",
            )
        return ProbeResult(
            method=ProbeMethod.HTTP_PROBE, target_ip=ip, port=str(port),
            protocol="http", verdict=ProbeVerdict.UNREACHABLE,
            error=str(e),
        )
    except Exception as e:
        return ProbeResult(
            method=ProbeMethod.HTTP_PROBE, target_ip=ip, port=str(port),
            protocol="http", verdict=ProbeVerdict.ERROR, error=str(e),
        )


async def probe_dns(ip: str, timeout: float = 5.0) -> ProbeResult:
    """DNS probe — sends a query to port 53 to test DNS service."""
    start = time.monotonic()
    try:
        # Build a simple DNS query for "." (root)
        # Transaction ID + Flags + Questions + Answer/Auth/Additional RRs
        query = (
            b"\xaa\xbb"  # Transaction ID
            b"\x01\x00"  # Standard query
            b"\x00\x01"  # 1 question
            b"\x00\x00\x00\x00\x00\x00"  # No answers/authority/additional
            b"\x00"  # Root domain
            b"\x00\x01"  # Type A
            b"\x00\x01"  # Class IN
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        loop = asyncio.get_event_loop()

        await loop.run_in_executor(None, sock.sendto, query, (ip, 53))

        try:
            data = await asyncio.wait_for(
                loop.run_in_executor(None, sock.recv, 512),
                timeout=timeout,
            )
            latency = (time.monotonic() - start) * 1000
            sock.close()
            return ProbeResult(
                method=ProbeMethod.DNS_PROBE, target_ip=ip, port="53",
                protocol="udp", verdict=ProbeVerdict.REACHABLE,
                latency_ms=round(latency, 2),
                details=f"DNS response received ({len(data)} bytes)",
            )
        except (asyncio.TimeoutError, socket.timeout):
            sock.close()
            return ProbeResult(
                method=ProbeMethod.DNS_PROBE, target_ip=ip, port="53",
                protocol="udp", verdict=ProbeVerdict.TIMEOUT,
                details="No DNS response — timed out",
            )
    except Exception as e:
        return ProbeResult(
            method=ProbeMethod.DNS_PROBE, target_ip=ip, port="53",
            protocol="udp", verdict=ProbeVerdict.ERROR, error=str(e),
        )


async def probe_firewall_api(
    src_ip: str, dst_ip: str, port: int, protocol: str,
    config: ProbeConfig,
) -> ProbeResult:
    """Query firewall management API to check if traffic would be allowed.

    Supports: Palo Alto (security-policy-match), Checkpoint, Fortinet.
    This is the most accurate method — asks the firewall directly without
    sending actual traffic.
    """
    import os

    if not config.firewall_api_url or not config.firewall_provider:
        return ProbeResult(
            method=ProbeMethod.FIREWALL_API, target_ip=dst_ip, port=str(port),
            protocol=protocol, verdict=ProbeVerdict.SKIPPED,
            details="Firewall API not configured",
        )

    api_key = ""
    if config.firewall_api_key_env:
        env_name = config.firewall_api_key_env.lstrip("$")
        api_key = os.environ.get(env_name, "")

    if not api_key:
        return ProbeResult(
            method=ProbeMethod.FIREWALL_API, target_ip=dst_ip, port=str(port),
            protocol=protocol, verdict=ProbeVerdict.SKIPPED,
            details=f"Firewall API key not found in env: {config.firewall_api_key_env}",
        )

    try:
        start = time.monotonic()
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            if config.firewall_provider == "palo_alto":
                # Palo Alto: test security-policy-match
                params = {
                    "type": "op",
                    "key": api_key,
                    "cmd": (
                        f"<test><security-policy-match>"
                        f"<source>{src_ip}</source>"
                        f"<destination>{dst_ip}</destination>"
                        f"<destination-port>{port}</destination-port>"
                        f"<protocol>{6 if protocol == 'tcp' else 17}</protocol>"
                        f"</security-policy-match></test>"
                    ),
                }
                resp = await client.get(config.firewall_api_url, params=params)
                latency = (time.monotonic() - start) * 1000

                body = resp.text
                if "allow" in body.lower() or "permit" in body.lower():
                    return ProbeResult(
                        method=ProbeMethod.FIREWALL_API, target_ip=dst_ip,
                        port=str(port), protocol=protocol,
                        verdict=ProbeVerdict.REACHABLE,
                        latency_ms=round(latency, 2),
                        details="Firewall policy PERMITS this traffic (Palo Alto policy-match)",
                    )
                elif "deny" in body.lower() or "drop" in body.lower():
                    return ProbeResult(
                        method=ProbeMethod.FIREWALL_API, target_ip=dst_ip,
                        port=str(port), protocol=protocol,
                        verdict=ProbeVerdict.UNREACHABLE,
                        latency_ms=round(latency, 2),
                        details="Firewall policy DENIES this traffic (Palo Alto policy-match)",
                    )
                else:
                    return ProbeResult(
                        method=ProbeMethod.FIREWALL_API, target_ip=dst_ip,
                        port=str(port), protocol=protocol,
                        verdict=ProbeVerdict.FILTERED,
                        latency_ms=round(latency, 2),
                        details=f"Firewall API response unclear: {body[:200]}",
                    )

            elif config.firewall_provider == "checkpoint":
                # Checkpoint: access-policy simulation
                payload = {
                    "source": src_ip,
                    "destination": dst_ip,
                    "service": f"{protocol}/{port}",
                }
                headers = {"X-chkp-sid": api_key}
                resp = await client.post(
                    f"{config.firewall_api_url}/web_api/run-script",
                    json=payload, headers=headers,
                )
                latency = (time.monotonic() - start) * 1000
                body = resp.json() if resp.status_code == 200 else {}
                action = body.get("action", "unknown")

                if action in ("accept", "allow"):
                    verdict = ProbeVerdict.REACHABLE
                elif action in ("drop", "reject", "deny"):
                    verdict = ProbeVerdict.UNREACHABLE
                else:
                    verdict = ProbeVerdict.FILTERED

                return ProbeResult(
                    method=ProbeMethod.FIREWALL_API, target_ip=dst_ip,
                    port=str(port), protocol=protocol, verdict=verdict,
                    latency_ms=round(latency, 2),
                    details=f"Checkpoint policy result: {action}",
                )

            elif config.firewall_provider == "fortinet":
                # Fortinet: policy lookup
                headers = {"Authorization": f"Bearer {api_key}"}
                params = {
                    "srcaddr": src_ip,
                    "dstaddr": dst_ip,
                    "service": f"{protocol.upper()}/{port}",
                }
                resp = await client.get(
                    f"{config.firewall_api_url}/api/v2/monitor/firewall/policy-lookup",
                    headers=headers, params=params,
                )
                latency = (time.monotonic() - start) * 1000
                body = resp.json() if resp.status_code == 200 else {}
                action = body.get("results", {}).get("action", "unknown")

                if action == "accept":
                    verdict = ProbeVerdict.REACHABLE
                elif action in ("deny", "drop"):
                    verdict = ProbeVerdict.UNREACHABLE
                else:
                    verdict = ProbeVerdict.FILTERED

                return ProbeResult(
                    method=ProbeMethod.FIREWALL_API, target_ip=dst_ip,
                    port=str(port), protocol=protocol, verdict=verdict,
                    latency_ms=round(latency, 2),
                    details=f"Fortinet policy result: {action}",
                )

    except Exception as e:
        return ProbeResult(
            method=ProbeMethod.FIREWALL_API, target_ip=dst_ip,
            port=str(port), protocol=protocol,
            verdict=ProbeVerdict.ERROR, error=str(e),
        )

    return ProbeResult(
        method=ProbeMethod.FIREWALL_API, target_ip=dst_ip,
        port=str(port), protocol=protocol, verdict=ProbeVerdict.SKIPPED,
        details=f"Unsupported firewall provider: {config.firewall_provider}",
    )


async def probe_ocp_api(
    namespace: str, pod_name: str, target_ip: str, port: int,
    protocol: str, config: ProbeConfig,
) -> ProbeResult:
    """Query K8s/OCP API to probe from inside a namespace.

    Uses 'exec' equivalent via K8s API (needs RBAC, no SSH).
    Runs: kubectl exec <pod> -- nc -z -w3 <target_ip> <port>
    """
    import os

    if not config.ocp_api_url:
        return ProbeResult(
            method=ProbeMethod.OCP_API, target_ip=target_ip, port=str(port),
            protocol=protocol, verdict=ProbeVerdict.SKIPPED,
            details="OCP API not configured",
        )

    token = ""
    if config.ocp_token_env:
        env_name = config.ocp_token_env.lstrip("$")
        token = os.environ.get(env_name, "")

    if not token:
        return ProbeResult(
            method=ProbeMethod.OCP_API, target_ip=target_ip, port=str(port),
            protocol=protocol, verdict=ProbeVerdict.SKIPPED,
            details="OCP API token not configured",
        )

    try:
        start = time.monotonic()
        # Use K8s exec API to run netcat from inside the pod
        exec_url = (
            f"{config.ocp_api_url}/api/v1/namespaces/{namespace}/pods/{pod_name}"
            f"/exec?command=nc&command=-z&command=-w3"
            f"&command={target_ip}&command={port}"
            f"&stdout=true&stderr=true"
        )
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            headers = {"Authorization": f"Bearer {token}"}
            resp = await client.post(exec_url, headers=headers)
            latency = (time.monotonic() - start) * 1000

            if resp.status_code == 200:
                return ProbeResult(
                    method=ProbeMethod.OCP_API, target_ip=target_ip,
                    port=str(port), protocol=protocol,
                    verdict=ProbeVerdict.REACHABLE,
                    latency_ms=round(latency, 2),
                    details=f"OCP exec from {namespace}/{pod_name}: port reachable",
                )
            else:
                return ProbeResult(
                    method=ProbeMethod.OCP_API, target_ip=target_ip,
                    port=str(port), protocol=protocol,
                    verdict=ProbeVerdict.UNREACHABLE,
                    latency_ms=round(latency, 2),
                    details=f"OCP exec returned status {resp.status_code}",
                )
    except Exception as e:
        return ProbeResult(
            method=ProbeMethod.OCP_API, target_ip=target_ip,
            port=str(port), protocol=protocol,
            verdict=ProbeVerdict.ERROR, error=str(e),
        )


# ---- Orchestrator ----

async def run_probes(
    src_ip: str | None,
    dst_ips: list[str],
    ports: list[str],
    config: ProbeConfig | None = None,
    methods: list[ProbeMethod] | None = None,
    max_probes: int = 20,
) -> list[ProbeResult]:
    """Run multi-method probes with fallback.

    For each destination IP + port combination:
      1. Try the first method in fallback_order
      2. If it returns SKIPPED or ERROR, try next method
      3. Stop on first definitive result (REACHABLE, UNREACHABLE, TIMEOUT, FILTERED)
    """
    if config is None:
        config = await load_probe_config()

    # Determine which methods to try
    available = methods or config.fallback_order
    available = [m for m in available if m not in config.disabled_methods]

    results: list[ProbeResult] = []
    probe_count = 0

    for dst_ip in dst_ips:
        # Handle CIDR — use first usable host
        actual_ip = dst_ip
        if "/" in dst_ip:
            try:
                net = ipaddress.ip_network(dst_ip, strict=False)
                hosts = list(net.hosts())
                if hosts:
                    actual_ip = str(hosts[0])
                else:
                    continue
            except ValueError:
                continue

        for port_spec in ports:
            if probe_count >= max_probes:
                break

            port_spec = port_spec.strip().lower()
            if "/" in port_spec:
                proto, port_num_str = port_spec.split("/", 1)
            else:
                proto, port_num_str = "tcp", port_spec

            try:
                port_num = int(port_num_str)
            except ValueError:
                continue

            # Try methods in fallback order
            for method in available:
                if probe_count >= max_probes:
                    break

                result: ProbeResult | None = None

                if method == ProbeMethod.TCP_SOCKET and proto == "tcp":
                    result = await probe_tcp_socket(actual_ip, port_num, config.timeout_seconds)
                elif method == ProbeMethod.ICMP_PING:
                    result = await probe_icmp_ping(actual_ip, config.timeout_seconds)
                elif method == ProbeMethod.TRACEROUTE:
                    result = await probe_traceroute(actual_ip, config.timeout_seconds * 2)
                elif method == ProbeMethod.HTTP_PROBE and port_num in (80, 443, 8080, 8443):
                    result = await probe_http(actual_ip, port_num, config.timeout_seconds)
                elif method == ProbeMethod.DNS_PROBE and port_num == 53:
                    result = await probe_dns(actual_ip, config.timeout_seconds)
                elif method == ProbeMethod.FIREWALL_API:
                    result = await probe_firewall_api(
                        src_ip or "0.0.0.0", actual_ip, port_num, proto, config
                    )
                elif method == ProbeMethod.OCP_API:
                    # OCP API needs namespace/pod context — skip in generic probing
                    continue

                if result:
                    results.append(result)
                    probe_count += 1
                    # Stop trying more methods if we got a definitive answer
                    if result.verdict in (
                        ProbeVerdict.REACHABLE, ProbeVerdict.UNREACHABLE,
                        ProbeVerdict.TIMEOUT, ProbeVerdict.FILTERED,
                    ):
                        break

    return results


async def run_probes_parallel(
    src_ip: str | None,
    dst_ips: list[str],
    ports: list[str],
    config: ProbeConfig | None = None,
    methods: list[ProbeMethod] | None = None,
) -> list[ProbeResult]:
    """Run all specified probes in parallel (for bulk mode)."""
    if config is None:
        config = await load_probe_config()

    available = methods or [config.fallback_order[0]] if config.fallback_order else [ProbeMethod.TCP_SOCKET]
    available = [m for m in available if m not in config.disabled_methods]

    tasks: list = []
    for dst_ip in dst_ips:
        actual_ip = dst_ip
        if "/" in dst_ip:
            try:
                net = ipaddress.ip_network(dst_ip, strict=False)
                hosts = list(net.hosts())
                actual_ip = str(hosts[0]) if hosts else dst_ip
            except ValueError:
                continue

        for port_spec in ports:
            port_spec = port_spec.strip().lower()
            if "/" in port_spec:
                proto, port_num_str = port_spec.split("/", 1)
            else:
                proto, port_num_str = "tcp", port_spec

            try:
                port_num = int(port_num_str)
            except ValueError:
                continue

            method = available[0] if available else ProbeMethod.TCP_SOCKET
            if method == ProbeMethod.TCP_SOCKET:
                tasks.append(probe_tcp_socket(actual_ip, port_num, config.timeout_seconds))
            elif method == ProbeMethod.HTTP_PROBE:
                tasks.append(probe_http(actual_ip, port_num, config.timeout_seconds))
            elif method == ProbeMethod.ICMP_PING:
                tasks.append(probe_icmp_ping(actual_ip, config.timeout_seconds))

    if not tasks:
        return []

    semaphore = asyncio.Semaphore(config.max_concurrent_probes)

    async def bounded(coro):
        async with semaphore:
            return await coro

    raw = await asyncio.gather(*[bounded(t) for t in tasks], return_exceptions=True)
    results = []
    for r in raw:
        if isinstance(r, ProbeResult):
            results.append(r)
        elif isinstance(r, Exception):
            results.append(ProbeResult(
                method=ProbeMethod.TCP_SOCKET, target_ip="unknown", port="unknown",
                protocol="tcp", verdict=ProbeVerdict.ERROR, error=str(r),
            ))
    return results
