"""
FyreWall - Gestor de Firewall & Debug de Puertos
Pestañas dinámicas tipo Chrome, cerrables, abiertas por comando o botón
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import re
import time
import ctypes
import os
import sys
import random
import socket
from PIL import Image, ImageTk

# ─── THEME ───────────────────────────────────────────────────────────────────

COLORS = {
    "bg":             "#1a1d23",
    "surface":        "#22252e",
    "surface2":       "#2a2d38",
    "border":         "#33374a",
    "accent":         "#4da6ff",
    "accent_hover":   "#6ab8ff",
    "text":           "#e8eaf0",
    "text_muted":     "#7a8099",
    "success":        "#4caf80",
    "warning":        "#f5a623",
    "danger":         "#e05c5c",
    "btn":            "#2a2d38",
    "btn_hover":      "#343848",
    "console_bg":     "#0e1117",
    "console_text":   "#c9d1d9",
    "console_prompt": "#4da6ff",
    "console_ok":     "#4caf80",
    "console_err":    "#e05c5c",
    "console_warn":   "#f5a623",
    "console_info":   "#7a8099",
    "red_dark":       "#3a0f0f",
    "red_btn":        "#8b2020",
    "red_active":     "#c0392b",
    "green_dark":     "#0f3a1a",
    "green_btn":      "#1e6b35",
    "green_active":   "#27ae60",
    "tab_active":     "#22252e",
    "tab_inactive":   "#191c22",
    "tab_hover":      "#2a2d38",
}

FONTS = {
    "title":    ("Segoe UI", 14, "bold"),
    "subtitle": ("Segoe UI", 10),
    "body":     ("Segoe UI", 10),
    "small":    ("Segoe UI", 9),
    "label":    ("Segoe UI", 8, "bold"),
    "button":   ("Segoe UI", 10, "bold"),
    "mono":     ("Consolas", 9),
    "mono_lg":  ("Consolas", 10),
}

# ─── ADMIN CHECK ──────────────────────────────────────────────────────────────

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

CF = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# ─── NETWORK SCANNER ─────────────────────────────────────────────────────────

def scan_connections() -> list[dict]:
    pid_to_name = {}
    try:
        tl = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"],
            text=True, timeout=10, creationflags=CF,
        )
        for line in tl.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                try:
                    pid_to_name[int(parts[1])] = parts[0]
                except ValueError:
                    pass
    except Exception:
        pass

    connections = []
    try:
        out = subprocess.check_output(
            ["netstat", "-ano"],
            text=True, timeout=15, creationflags=CF,
        )
    except Exception:
        return connections

    for line in out.splitlines():
        line = line.strip()
        m = re.match(
            r"(TCP|UDP)\s+([\d\.\[\]:]+):(\d+)\s+([\d\.\[\]:*]+):(\d*)\s+(\w[\w_\s]*)?\s*(\d+)$",
            line,
        )
        if not m:
            continue
        proto       = m.group(1)
        local_addr  = m.group(2)
        local_port  = int(m.group(3))
        remote_addr = m.group(4)
        remote_port = m.group(5) or "*"
        state       = m.group(6).strip() if m.group(6) else "—"
        pid         = int(m.group(7))

        name = pid_to_name.get(pid, f"PID {pid}")
        connections.append({
            "pid":          pid,
            "process":      name,
            "proto":        proto,
            "local_addr":   local_addr,
            "local_port":   local_port,
            "remote_addr":  remote_addr,
            "remote_port":  remote_port,
            "state":        state,
        })

    return connections


def get_active_connections_for_requests() -> list[dict]:
    """Get connections grouped by process for the Requests tab."""
    conns = scan_connections()
    grouped = {}
    for c in conns:
        if c["remote_addr"] in ("0.0.0.0", "[::]", "*", "127.0.0.1") or c["remote_port"] == "*":
            continue
        proc = c["process"]
        if proc not in grouped:
            grouped[proc] = {
                "process": proc,
                "pid": c["pid"],
                "connections": [],
                "remote_hosts": set(),
            }
        grouped[proc]["connections"].append(c)
        grouped[proc]["remote_hosts"].add(c["remote_addr"])

    result = []
    for proc, data in grouped.items():
        if data["connections"]:
            result.append({
                "process":      data["process"],
                "pid":          data["pid"],
                "connections":  data["connections"],
                "remote_hosts": list(data["remote_hosts"]),
                "conn_count":   len(data["connections"]),
            })

    result.sort(key=lambda x: x["conn_count"], reverse=True)
    return result


# ─── GET-IP ──────────────────────────────────────────────────────────────────

# ─── SUSPICIOUS PORT SCANNER ─────────────────────────────────────────────────

SUSPICIOUS_PORTS = {
    # ── Screen sharing / remote control ──────────────────────────────────
    5900:  ("🖥️  VNC",             "screen_share",  "Control remoto / compartir pantalla (VNC estándar)"),
    5901:  ("🖥️  VNC-1",           "screen_share",  "Control remoto VNC instancia 1"),
    5902:  ("🖥️  VNC-2",           "screen_share",  "Control remoto VNC instancia 2"),
    3389:  ("🖥️  RDP",             "screen_share",  "Escritorio Remoto de Windows (RDP)"),
    3388:  ("🖥️  RDP-alt",         "screen_share",  "RDP puerto alternativo"),
    5938:  ("🖥️  TeamViewer",      "screen_share",  "TeamViewer — control remoto / compartir pantalla"),
    49175: ("🖥️  TeamViewer-UDP",  "screen_share",  "TeamViewer comunicación interna"),
    7070:  ("🖥️  RealVNC",         "screen_share",  "RealVNC Cloud relay"),
    4899:  ("🖥️  Radmin",          "screen_share",  "Radmin remote admin"),
    8833:  ("🖥️  Supremo",         "screen_share",  "Supremo Remote Desktop"),
    5650:  ("🖥️  ZohoAssist",      "screen_share",  "Zoho Assist remote support"),
    1494:  ("🖥️  Citrix ICA",      "screen_share",  "Citrix ICA — acceso remoto corporativo"),
    2598:  ("🖥️  Citrix CGP",      "screen_share",  "Citrix Session Reliability"),
    796:   ("🎓  Insight legacy",   "screen_share",  "Faronics Insight Student (legacy)"),
    11796: ("🎓  Insight modern",   "screen_share",  "Faronics Insight Student (moderno)"),
    8888:  ("🎓  Insight WS",       "screen_share",  "Faronics Insight WebSocket"),
    8889:  ("🎓  Insight WS-2",     "screen_share",  "Faronics Insight WebSocket"),
    8890:  ("🎓  Insight WS-3",     "screen_share",  "Faronics Insight WebSocket"),
    9000:  ("🔄  RR Endpoint",      "screen_share",  "Reboot Restore Enterprise Endpoint"),
    5901:  ("🔄  RR VNC",           "screen_share",  "Reboot Restore VNC"),
    # ── File sharing ─────────────────────────────────────────────────────
    445:   ("📁  SMB",             "file_share",    "Compartir archivos Windows (SMB/CIFS)"),
    139:   ("📁  NetBIOS",         "file_share",    "NetBIOS Session Service (archivos legacy)"),
    137:   ("📁  NetBIOS-NS",      "file_share",    "NetBIOS Name Service"),
    138:   ("📁  NetBIOS-DG",      "file_share",    "NetBIOS Datagram Service"),
    21:    ("📁  FTP",             "file_share",    "FTP — transferencia de archivos en claro"),
    20:    ("📁  FTP-data",        "file_share",    "FTP datos"),
    22:    ("📁  SSH/SFTP",        "file_share",    "SSH / SFTP — puede usarse para transferir archivos"),
    69:    ("📁  TFTP",            "file_share",    "TFTP — transferencia de archivos sin autenticación"),
    2049:  ("📁  NFS",             "file_share",    "NFS Network File System"),
    548:   ("📁  AFP",             "file_share",    "Apple Filing Protocol"),
    5005:  ("📁  ShareFile",       "file_share",    "Citrix ShareFile / transfer"),
    5006:  ("📁  ShareFile-2",     "file_share",    "Citrix ShareFile secundario"),
    80:    ("📁  HTTP",            "file_share",    "HTTP — podría ser WebDAV / compartir archivos web"),
    8080:  ("📁  HTTP-alt",        "file_share",    "HTTP alternativo / posible WebDAV"),
    # ── Diagnostics / telemetry / monitoring ──────────────────────────────
    161:   ("📊  SNMP",            "telemetry",     "SNMP — monitorización de red / diagnósticos"),
    162:   ("📊  SNMP-trap",       "telemetry",     "SNMP Trap — alertas de diagnóstico"),
    514:   ("📊  Syslog",          "telemetry",     "Syslog — envío de logs del sistema"),
    6514:  ("📊  Syslog-TLS",      "telemetry",     "Syslog sobre TLS"),
    9100:  ("📊  JetDirect/mon",   "telemetry",     "Monitor de impresión / diagnóstico"),
    25:    ("📧  SMTP",            "telemetry",     "SMTP — puede enviar informes por correo"),
    8125:  ("📊  StatsD",          "telemetry",     "StatsD métricas de telemetría"),
    4317:  ("📊  OpenTelemetry",   "telemetry",     "OpenTelemetry gRPC"),
    4318:  ("📊  OpenTelem-HTTP",  "telemetry",     "OpenTelemetry HTTP"),
    9090:  ("📊  Prometheus",      "telemetry",     "Prometheus scraping de métricas"),
    3000:  ("📊  Grafana",         "telemetry",     "Grafana dashboard / métricas"),
    5044:  ("📊  Logstash",        "telemetry",     "Logstash — recolección de logs"),
    5601:  ("📊  Kibana",          "telemetry",     "Kibana — visualización de logs"),
    9200:  ("📊  Elasticsearch",   "telemetry",     "Elasticsearch — indexación de logs/diagnósticos"),
    1053:  ("🎓  Insight-diag",    "telemetry",     "Faronics Insight status broadcast / diagnóstico"),
}

CATEGORY_NAMES = {
    "screen_share": "🖥️  COMPARTIR PANTALLA / CONTROL REMOTO",
    "file_share":   "📁  COMPARTIR ARCHIVOS",
    "telemetry":    "📊  DIAGNÓSTICOS / TELEMETRÍA",
}


def scan_suspicious_ports() -> dict:
    """Scan active connections and match against suspicious port list."""
    conns = scan_connections()
    findings: dict[str, list[dict]] = {"screen_share": [], "file_share": [], "telemetry": []}
    seen = set()

    for c in conns:
        port = c["local_port"]
        if port in SUSPICIOUS_PORTS:
            icon, category, reason = SUSPICIOUS_PORTS[port]
            key = (port, c["process"])
            if key in seen:
                continue
            seen.add(key)
            findings[category].append({
                "port":    port,
                "icon":    icon,
                "reason":  reason,
                "process": c["process"],
                "pid":     c["pid"],
                "state":   c["state"],
                "proto":   c["proto"],
            })

    return findings


def get_ip_info() -> str:
    """Return local and public IP information."""
    lines = ["Información de Red:", "─" * 50]

    # Local network interfaces
    lines.append("\n  📡  REDES LOCALES:")
    try:
        out = subprocess.check_output(
            ["ipconfig"],
            text=True, timeout=10, creationflags=CF, encoding="cp850", errors="replace"
        )
        adapter = None
        ipv4 = None
        mask = None
        gateway = None
        for line in out.splitlines():
            line_s = line.strip()
            # Detect adapter header
            if line_s and not line_s.startswith(" ") and ":" in line_s and not any(
                k in line_s for k in ("IPv4", "IPv6", "Máscara", "Puerta", "Subnet", "Gateway", "DNS", "DHCP", "Autoconfiguration")
            ):
                # flush previous adapter
                if adapter and ipv4:
                    lines.append(f"    🔌  {adapter}")
                    lines.append(f"        IPv4:     {ipv4}")
                    if mask:
                        lines.append(f"        Máscara:  {mask}")
                    if gateway:
                        lines.append(f"        Gateway:  {gateway}")
                adapter = line_s.rstrip(":")
                ipv4 = mask = gateway = None

            if "IPv4" in line_s or ("Dirección IP" in line_s and "IPv6" not in line_s):
                ipv4 = line_s.split(":", 1)[-1].strip().rstrip(" (Preferred)").rstrip("(Preferido)")
            elif "Máscara de subred" in line_s or "Subnet Mask" in line_s:
                mask = line_s.split(":", 1)[-1].strip()
            elif "Puerta de enlace predeterminada" in line_s or "Default Gateway" in line_s:
                gw = line_s.split(":", 1)[-1].strip()
                if gw:
                    gateway = gw

        # flush last
        if adapter and ipv4:
            lines.append(f"    🔌  {adapter}")
            lines.append(f"        IPv4:     {ipv4}")
            if mask:
                lines.append(f"        Máscara:  {mask}")
            if gateway:
                lines.append(f"        Gateway:  {gateway}")
    except Exception as e:
        lines.append(f"    ❌  Error obteniendo IPs locales: {e}")

    # Public IP
    lines.append("\n  🌐  IP PÚBLICA:")
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
            pub_ip = resp.read().decode().strip()
        lines.append(f"    🌍  IPv4 Pública: {pub_ip}")
    except Exception:
        try:
            with urllib.request.urlopen("https://ident.me", timeout=5) as resp:
                pub_ip = resp.read().decode().strip()
            lines.append(f"    🌍  IPv4 Pública: {pub_ip}")
        except Exception as e:
            lines.append(f"    ⚠️   No se pudo obtener la IP pública: {e}")

    return "\n".join(lines)


# ─── FIREWALL COMMANDS ───────────────────────────────────────────────────────

RULE_PREFIX = "FyreWall_"

def _run(args: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=10, creationflags=CF
        )
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()
        return True, r.stdout.strip()
    except Exception as e:
        return False, str(e)


def _rule_exists(rule_name: str) -> bool:
    """Check if a firewall rule with this exact name already exists."""
    ok, out = _run([
        "netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}",
    ])
    return ok and "No rules match" not in out and rule_name in out


def cmd_block_port(port: int, proto: str = "TCP", direction: str = "in") -> tuple[bool, str, str]:
    name = f"{RULE_PREFIX}Block_{proto}_{direction.upper()}_{port}"
    if _rule_exists(name):
        return True, "ya existe", name
    ok, msg = _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name}", f"protocol={proto.upper()}", f"dir={direction}",
        f"localport={port}", "action=block",
    ])
    return ok, msg, name


def cmd_unblock_port(port: int, proto: str = "TCP", direction: str = "in") -> tuple[bool, str]:
    name = f"{RULE_PREFIX}Block_{proto}_{direction.upper()}_{port}"
    ok, msg = _run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={name}",
    ])
    return ok, msg


def cmd_block_app(path: str) -> tuple[bool, str]:
    name = f"{RULE_PREFIX}App_{os.path.basename(path)}"
    ok, msg = _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name}", "dir=out", "action=block",
        f"program={path}", "enable=yes",
    ])
    return ok, msg


def cmd_list_rules() -> dict:
    """List all ports/rules blocked by FyreWall."""
    # netsh wildcard 'name=FyreWall_*' does NOT work — must dump all and filter
    ok, out = _run([
        "netsh", "advfirewall", "firewall", "show", "rule", "name=all",
    ])
    if not ok or not out.strip():
        return {}

    # Parse into structured port list, keeping only FyreWall_ rules
    ports_found = {}
    current_name = None
    current_proto = None
    current_port = None
    current_dir = None
    current_action = None

    def _flush():
        nonlocal current_name, current_proto, current_port, current_dir, current_action
        if current_name and current_name.startswith(RULE_PREFIX):
            if current_port and current_port not in ("Any", "any", ""):
                key = f"{current_port}/{current_proto or 'ANY'}"
                if key not in ports_found:
                    ports_found[key] = {
                        "name": current_name,
                        "port": current_port,
                        "proto": current_proto or "ANY",
                        "dirs": [],
                        "action": current_action or "Block",
                    }
                if current_dir and current_dir not in ports_found[key]["dirs"]:
                    ports_found[key]["dirs"].append(current_dir)
        current_name = current_proto = current_port = current_dir = current_action = None

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Rule Name:"):
            _flush()
            current_name = line.split(":", 1)[1].strip()
        elif line.startswith("Protocol:"):
            current_proto = line.split(":", 1)[1].strip()
        elif line.startswith("LocalPort:") or line.startswith("Local Port:"):
            current_port = line.split(":", 1)[1].strip()
        elif line.startswith("Direction:"):
            current_dir = line.split(":", 1)[1].strip()
        elif line.startswith("Action:"):
            current_action = line.split(":", 1)[1].strip()

    _flush()  # flush last rule
    return ports_found


def cmd_flush_all() -> tuple[bool, str]:
    ok, msg = _run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={RULE_PREFIX}*",
    ])
    return ok, msg


def cmd_isolate(enable: bool) -> tuple[bool, str]:
    if enable:
        ok1, m1 = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=FyreWall_ISOLATE_IN", "dir=in", "action=block", "protocol=any",
        ])
        ok2, m2 = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=FyreWall_ISOLATE_OUT", "dir=out", "action=block", "protocol=any",
        ])
        return (ok1 and ok2), (m1 or m2)
    else:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=FyreWall_ISOLATE_IN"])
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=FyreWall_ISOLATE_OUT"])
        return True, ""


def cmd_block_process(proc_name: str) -> tuple[bool, str]:
    name = f"{RULE_PREFIX}Proc_{proc_name.replace('.', '_')}"
    ps = (
        f"$p = Get-Process | Where-Object {{$_.Name -like '{proc_name.replace('.exe','')}*'}} "
        f"| Select-Object -First 1; "
        f"if ($p) {{ New-NetFirewallRule -DisplayName '{name}' -Direction Outbound -Action Block "
        f"-Program $p.Path -ErrorAction Stop }} else {{ Write-Error 'Proceso no encontrado' }}"
    )
    ok, msg = _run(["powershell", "-WindowStyle", "Hidden", "-Command", ps])
    return ok, msg


def cmd_block_app_by_name(app_name: str) -> tuple[bool, str]:
    """Block a firewall app by executable name or path."""
    ps = (
        f"$p = Get-Process | Where-Object {{$_.Name -like '{app_name.replace('.exe','')}*'}} "
        f"| Select-Object -First 1; "
        f"if ($p) {{"
        f"  $ruleName = 'FyreWall_AppBlock_{app_name.replace(' ','_')}'; "
        f"  New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block "
        f"  -Program $p.Path -ErrorAction Stop "
        f"}} else {{ Write-Error 'Proceso no encontrado: {app_name}' }}"
    )
    ok, msg = _run(["powershell", "-WindowStyle", "Hidden", "-Command", ps])
    return ok, msg


# ─── SERVICE STATUS CHECK ────────────────────────────────────────────────────

def check_service_status(service_name: str) -> str:
    """Returns 'running', 'stopped', 'not_found'"""
    try:
        r = subprocess.run(
            ["sc", "query", service_name],
            capture_output=True, text=True, timeout=5, creationflags=CF
        )
        if r.returncode != 0 or "FAILED" in r.stdout:
            return "not_found"
        if "RUNNING" in r.stdout:
            return "running"
        return "stopped"
    except Exception:
        return "not_found"


CLASSROOM_SERVICES = {
    "insight": [
        "FaronicsInsightStudent",
        "InsightConnectionService",
        "FaronicsInsight",
        "InsSvc",
    ],
    "rebootrestore": [
        "RmServer",
        "RmClientSvc",
        "RebootRestoreRx",
        "RmClient",
    ],
}


def check_classroom_services_status() -> dict:
    """Check if Insight and RebootRestore services are running."""
    result = {
        "insight": {"status": "not_found", "service": None},
        "rebootrestore": {"status": "not_found", "service": None},
    }
    for app_key, services in CLASSROOM_SERVICES.items():
        for svc in services:
            status = check_service_status(svc)
            if status in ("running", "stopped"):
                result[app_key]["status"] = status
                result[app_key]["service"] = svc
                break
    return result


# ─── CLASSROOM RULES ─────────────────────────────────────────────────────────

CLASSROOM_RULES = {
    "insight": [
        {"port": 796,   "proto": "UDP", "dir": "in",  "name": "Insight_UDP796_IN"},
        {"port": 796,   "proto": "UDP", "dir": "out", "name": "Insight_UDP796_OUT"},
        {"port": 796,   "proto": "TCP", "dir": "in",  "name": "Insight_TCP796_IN"},
        {"port": 796,   "proto": "TCP", "dir": "out", "name": "Insight_TCP796_OUT"},
        {"port": 11796, "proto": "UDP", "dir": "in",  "name": "Insight_UDP11796_IN"},
        {"port": 11796, "proto": "UDP", "dir": "out", "name": "Insight_UDP11796_OUT"},
        {"port": 11796, "proto": "TCP", "dir": "in",  "name": "Insight_TCP11796_IN"},
        {"port": 11796, "proto": "TCP", "dir": "out", "name": "Insight_TCP11796_OUT"},
        {"port": 1053,  "proto": "UDP", "dir": "in",  "name": "Insight_UDP1053_IN"},
        {"port": 1053,  "proto": "UDP", "dir": "out", "name": "Insight_UDP1053_OUT"},
        {"port": 8888,  "proto": "TCP", "dir": "in",  "name": "Insight_WS8888_IN"},
        {"port": 8888,  "proto": "TCP", "dir": "out", "name": "Insight_WS8888_OUT"},
        {"port": 8889,  "proto": "TCP", "dir": "in",  "name": "Insight_WS8889_IN"},
        {"port": 8889,  "proto": "TCP", "dir": "out", "name": "Insight_WS8889_OUT"},
        {"port": 8890,  "proto": "TCP", "dir": "in",  "name": "Insight_WS8890_IN"},
        {"port": 8890,  "proto": "TCP", "dir": "out", "name": "Insight_WS8890_OUT"},
        {"port_range": "10000-20000", "proto": "TCP", "dir": "in",  "name": "Insight_RC_IN"},
        {"port_range": "10000-20000", "proto": "TCP", "dir": "out", "name": "Insight_RC_OUT"},
    ],
    "rebootrestore": [
        {"port": 9000, "proto": "TCP", "dir": "in",  "name": "RR_EP9000_IN"},
        {"port": 9000, "proto": "TCP", "dir": "out", "name": "RR_EP9000_OUT"},
        {"port": 5900, "proto": "TCP", "dir": "in",  "name": "RR_VNC5900_IN"},
        {"port": 5900, "proto": "TCP", "dir": "out", "name": "RR_VNC5900_OUT"},
        {"port": 9001, "proto": "TCP", "dir": "in",  "name": "RR_EP9001_IN"},
        {"port": 9001, "proto": "TCP", "dir": "out", "name": "RR_EP9001_OUT"},
        {"port": 9010, "proto": "TCP", "dir": "in",  "name": "RR_EP9010_IN"},
        {"port": 9010, "proto": "TCP", "dir": "out", "name": "RR_EP9010_OUT"},
    ],
}

CLASSROOM_PROCESSES = {
    "insight": ["InsSvc", "InsStudent", "FnF", "InsConnSvc"],
    "rebootrestore": ["RmClient", "RmServer", "RmConsole"],
}


def _block_port_range(port_range: str, proto: str, direction: str, rule_name: str) -> tuple[bool, str]:
    full_name = f"{RULE_PREFIX}{rule_name}"
    if _rule_exists(full_name):
        return True, "ya existe"
    ok, msg = _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={full_name}", f"protocol={proto.upper()}", f"dir={direction}",
        f"localport={port_range}", "action=block",
    ])
    return ok, msg


def apply_classroom_block(app_key: str, log_callback=None) -> dict:
    rules = CLASSROOM_RULES.get(app_key, [])
    results = {"ok": 0, "fail": 0, "skipped": 0, "messages": []}

    def log(msg):
        results["messages"].append(msg)
        if log_callback:
            log_callback(msg)

    # ── 1. Stop & disable services first ─────────────────────────────────
    log("  🛑 Deteniendo servicios...")
    found_any_service = False
    for svc in CLASSROOM_SERVICES.get(app_key, []):
        status = check_service_status(svc)
        if status == "running":
            found_any_service = True
            _run(["sc", "stop", svc])
            _run(["sc", "config", svc, "start=", "disabled"])
            log(f"  🛑 Servicio detenido y deshabilitado: {svc}")
        elif status == "stopped":
            found_any_service = True
            _run(["sc", "config", svc, "start=", "disabled"])
            log(f"  ⏹️  Servicio ya detenido, deshabilitado: {svc}")
    if not found_any_service:
        log("  ℹ️  No se encontraron servicios activos (puede que no esté instalado).")

    # ── 2. Kill running processes ─────────────────────────────────────────
    for proc in CLASSROOM_PROCESSES.get(app_key, []):
        ok, msg = cmd_block_process(proc)
        if ok:
            results["ok"] += 1
            log(f"  ✅ Proceso bloqueado: {proc}")
        else:
            log(f"  ℹ️  Proceso no activo: {proc}")

    # ── 3. Apply firewall rules ───────────────────────────────────────────
    log("  🔒 Aplicando reglas de firewall...")
    for rule in rules:
        name = rule["name"]
        proto = rule["proto"]
        direction = rule["dir"]
        full_name = f"{RULE_PREFIX}{name}"

        # Check if rule already exists — skip silently
        if _rule_exists(full_name):
            results["skipped"] += 1
            results["ok"] += 1
            if "port_range" in rule:
                label = f"{proto} {rule['port_range']} {direction.upper()}"
            else:
                label = f"{proto} {rule['port']} {direction.upper()}"
            log(f"  ⏭️  Ya existía: {label}")
            continue

        if "port_range" in rule:
            ok, msg = _block_port_range(rule["port_range"], proto, direction, name)
            label = f"{proto} {rule['port_range']} {direction.upper()}"
        else:
            port = rule["port"]
            ok, msg, _ = cmd_block_port(port, proto, direction)
            label = f"{proto} {port} {direction.upper()}"

        if ok:
            results["ok"] += 1
            log(f"  ✅ Bloqueado: {label}  →  {full_name}")
        else:
            results["fail"] += 1
            log(f"  ❌ Error {label}: {msg[:80]}")

    return results


def remove_classroom_block(app_key: str, log_callback=None) -> dict:
    rules = CLASSROOM_RULES.get(app_key, [])
    results = {"ok": 0, "fail": 0, "messages": []}

    def log(msg):
        results["messages"].append(msg)
        if log_callback:
            log_callback(msg)

    for rule in rules:
        name = f"{RULE_PREFIX}{rule['name']}"
        ok, msg = _run([
            "netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}",
        ])
        if ok:
            results["ok"] += 1
            log(f"  ✅ Eliminada: {name}")
        else:
            results["fail"] += 1
            log(f"  ⚠️  No encontrada: {name}")

    return results


def create_persistent_startup_task(app_key: str) -> tuple[bool, str]:
    task_name = f"FyreWall_ClassroomBlock_{app_key}"
    lines = ["@echo off"]
    for rule in CLASSROOM_RULES.get(app_key, []):
        proto = rule["proto"].upper()
        direction = rule["dir"]
        full_name = f"{RULE_PREFIX}{rule['name']}"
        port_spec = rule.get("port_range") or str(rule.get("port"))
        lines.append(
            f'netsh advfirewall firewall add rule name="{full_name}" '
            f'protocol={proto} dir={direction} localport={port_spec} action=block >nul 2>&1'
        )

    bat_path = os.path.join(
        os.environ.get("ProgramData", "C:\\ProgramData"),
        f"FyreWall_{task_name}.bat"
    )
    try:
        with open(bat_path, "w") as f:
            f.write("\n".join(lines))
    except Exception as e:
        return False, f"No se pudo escribir el script: {e}"

    ps = (
        f'$action = New-ScheduledTaskAction -Execute "{bat_path}"; '
        f'$trigger = New-ScheduledTaskTrigger -AtStartup; '
        f'$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2); '
        f'$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest; '
        f'Register-ScheduledTask -TaskName "{task_name}" -Action $action '
        f'-Trigger $trigger -Settings $settings -Principal $principal -Force'
    )
    ok, msg = _run(["powershell", "-WindowStyle", "Hidden", "-Command", ps])
    return ok, msg


def disable_classroom_services(app_key: str) -> list[str]:
    results = []
    for svc in CLASSROOM_SERVICES.get(app_key, []):
        status = check_service_status(svc)
        if status == "not_found":
            results.append(f"  ℹ️  Servicio no encontrado: {svc}")
            continue
        # Stop first, then disable
        _run(["sc", "stop", svc])
        ok, msg = _run(["sc", "config", svc, "start=", "disabled"])
        if ok:
            results.append(f"  ✅ Servicio deshabilitado y detenido: {svc}")
        else:
            results.append(f"  ⚠️  Error al deshabilitar {svc}: {msg[:60]}")
    return results


# ─── CONSOLE COMMAND PARSER ──────────────────────────────────────────────────

COMMANDS = [
    ("block-port ",        "block-port <puerto> [tcp|udp] [in|out]"),
    ("unblock-port ",      "unblock-port <puerto> [tcp|udp] [in|out]"),
    ("block-app ",         "block-app <ruta_exe>"),
    ("block-process ",     "block-process <nombre>"),
    ("block-insight",      "block-insight — bloquea Faronics Insight Student"),
    ("unblock-insight",    "unblock-insight — desbloquea Faronics Insight"),
    ("block-reboot",       "block-reboot — bloquea Reboot Restore Enterprise"),
    ("unblock-reboot",     "unblock-reboot — desbloquea Reboot Restore"),
    ("list",               "list — muestra todos los puertos bloqueados por FyreWall"),
    ("flush",              "flush — elimina todas las reglas FyreWall"),
    ("isolate",            "isolate — bloquea TODO el tráfico"),
    ("unisolate",          "unisolate — restaura la red"),
    ("status ",            "status <puerto>"),
    ("scan",               "scan — re-escanea conexiones"),
    ("get-admin",          "get-admin — solicita privilegios de Administrador"),
    ("get-ip",             "get-ip — muestra todas tus IPs locales y pública"),
    ("get-suspicious",     "get-suspicious — analiza puertos sospechosos (compartir pantalla, archivos, diagnóstico)"),
    ("get-bat",            "get-bat — explorador de archivos .bat para ejecutar"),
    ("run-bat ",           "run-bat <archivo.bat> — ejecuta un .bat del directorio"),
    ("ls",                 "ls — lista archivos del directorio de FyreWall"),
    ("peticiones",         "peticiones — abre la pestaña de peticiones de red"),
    ("monitor",            "monitor — abre el Debug Monitor"),
    ("aula",               "aula — abre el Bloqueo de Aula"),
    ("clear",              "clear — limpia la consola"),
    ("help",               "help — muestra ayuda"),
]

# Directory where the app lives (for ls / run-bat)
APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))

HELP_TEXT = """\
╔══════════════════════════════════════════════════════════════╗
║              FyreWall — Comandos disponibles                 ║
╚══════════════════════════════════════════════════════════════╝

  PUERTOS
  ─────────────────────────────────────────────────────────────
  block-port <puerto> [tcp|udp] [in|out]
      Bloquea un puerto. Protocolo y dirección son opcionales.
      Ej: block-port 8080
          block-port 3389 tcp in

  unblock-port <puerto> [tcp|udp] [in|out]
      Elimina la regla de bloqueo para ese puerto.

  status <puerto>
      Comprueba si hay una regla de bloqueo para ese puerto.

  APLICACIONES
  ─────────────────────────────────────────────────────────────
  block-app <ruta_exe>
      Bloquea el tráfico saliente de un ejecutable específico.

  block-process <nombre>
      Bloquea el proceso en ejecución por nombre.

  VIGILANCIA DE AULA
  ─────────────────────────────────────────────────────────────
  block-insight
      Bloquea Faronics Insight Student (todos los puertos y
      procesos conocidos: UDP/TCP 796, 11796, 1053, WS 8888-
      8890, RC 10000-20000).

  unblock-insight
      Desbloquea Faronics Insight Student.

  block-reboot
      Bloquea Reboot Restore Enterprise (TCP 9000, 5900, VNC).

  unblock-reboot
      Desbloquea Reboot Restore Enterprise.

  SISTEMA
  ─────────────────────────────────────────────────────────────
  get-suspicious
      Analiza los puertos activos en busca de actividad sospechosa:
      compartir pantalla (VNC, RDP, TeamViewer…), compartir archivos
      (SMB, FTP, WebDAV…) y envío de diagnósticos/telemetría.
      Muestra qué proceso usa cada puerto y permite bloquearlo.

  get-admin
      Solicita privilegios de Administrador a Windows (UAC).
      Si ya eres admin, lo indica.

  get-ip
      Muestra todas las redes locales a las que estás conectado
      y tu dirección IP pública actual.

  ARCHIVOS BATCH
  ─────────────────────────────────────────────────────────────
  get-bat
      Abre un explorador de archivos para seleccionar un .bat
      y ejecutarlo en una nueva pestaña "Batch".

  ls
      Lista todos los archivos del directorio donde está FyreWall.
      Los archivos .bat se marcan y pueden ejecutarse con run-bat.

  run-bat <archivo.bat>
      Ejecuta un archivo .bat del directorio de FyreWall en una
      nueva pestaña "Batch" (con autocompletado por Tab).

  GENERAL
  ─────────────────────────────────────────────────────────────
  list      Lista TODOS los puertos bloqueados por FyreWall.
  flush     Elimina TODAS las reglas creadas por FyreWall.
  isolate   Bloquea TODO el tráfico de red.
  unisolate Restaura el acceso a la red.
  scan      Fuerza re-escaneo en el Debug Monitor.
  clear     Limpia la consola.

  PESTAÑAS
  ─────────────────────────────────────────────────────────────
  peticiones  Abre la pestaña de peticiones de red en vivo.
  monitor     Abre el Debug Monitor de conexiones.
  aula        Abre el panel de Bloqueo de Aula.
  help        Muestra esta ayuda.
──────────────────────────────────────────────────────────────
"""


def parse_and_run(command: str) -> tuple[str, str]:
    parts = command.strip().split()
    if not parts:
        return "", "info"

    cmd = parts[0].lower()

    if cmd in ("help", "?"):
        return HELP_TEXT, "info"
    if cmd == "clear":
        return "__CLEAR__", "info"
    if cmd == "scan":
        return "__SCAN__", "info"
    if cmd == "peticiones":
        return "__OPEN_PETICIONES__", "info"
    if cmd == "monitor":
        return "__OPEN_MONITOR__", "info"
    if cmd == "aula":
        return "__OPEN_AULA__", "info"

    if cmd == "get-admin":
        return "__GET_ADMIN__", "info"

    if cmd == "get-suspicious":
        return "__GET_SUSPICIOUS__", "info"

    if cmd == "get-ip":
        return "__GET_IP__", "info"

    if cmd == "get-bat":
        return "__GET_BAT__", "info"

    if cmd == "ls":
        try:
            entries = sorted(os.listdir(APP_DIR))
            lines = [f"📁  Directorio: {APP_DIR}", "─" * 50]
            bats = []
            for name in entries:
                full = os.path.join(APP_DIR, name)
                is_bat = name.lower().endswith(".bat")
                is_dir = os.path.isdir(full)
                if is_dir:
                    lines.append(f"  📂  {name}/")
                elif is_bat:
                    lines.append(f"  🟡  {name}  ← ejecutable con run-bat {name}")
                    bats.append(name)
                else:
                    lines.append(f"  📄  {name}")
            if bats:
                lines.append(f"\n  {len(bats)} archivo(s) .bat disponible(s). Usa: run-bat <nombre>")
            return "\n".join(lines), "info"
        except Exception as e:
            return f"❌  Error listando directorio: {e}", "error"

    if cmd == "run-bat":
        if len(parts) < 2:
            return "Uso: run-bat <archivo.bat>", "warn"
        bat_name = parts[1]
        # Allow partial name without extension
        if not bat_name.lower().endswith(".bat"):
            bat_name += ".bat"
        bat_path = os.path.join(APP_DIR, bat_name)
        if not os.path.isfile(bat_path):
            # Try search in APP_DIR
            return f"❌  No se encontró '{bat_name}' en {APP_DIR}\n    Usa 'ls' para ver los archivos disponibles.", "error"
        return f"__RUN_BAT__{bat_path}", "info"

    if cmd == "list":
        ports = cmd_list_rules()
        if not ports:
            return "No hay puertos bloqueados por FyreWall.\n(Usa 'block-port <puerto>' para bloquear uno.)", "warn"
        lines = ["Puertos bloqueados por FyreWall:", "─" * 50]
        for key, info in ports.items():
            dirs = ", ".join(info["dirs"]) if info["dirs"] else "—"
            lines.append(f"  🔒 {info['port']:20s}  {info['proto']:5s}  dirs: {dirs}")
            lines.append(f"     Regla: {info['name']}")
        lines.append(f"\n  Total: {len(ports)} regla(s)")
        return "\n".join(lines), "info"

    if cmd == "flush":
        ok, msg = cmd_flush_all()
        if ok:
            return "✅  Todas las reglas de FyreWall eliminadas.", "ok"
        return f"❌  Error al eliminar reglas:\n{msg}", "error"

    if cmd == "isolate":
        ok, msg = cmd_isolate(True)
        if ok:
            return "🔴  EQUIPO AISLADO — Todo el tráfico de red bloqueado.", "warn"
        return f"❌  Error al aislar:\n{msg}", "error"

    if cmd == "unisolate":
        ok, msg = cmd_isolate(False)
        if ok:
            return "🟢  Aislamiento eliminado — Red restaurada.", "ok"
        return f"❌  Error al restaurar red:\n{msg}", "error"

    if cmd == "block-insight":
        return "__BLOCK_INSIGHT__", "info"

    if cmd == "unblock-insight":
        return "__UNBLOCK_INSIGHT__", "info"

    if cmd == "block-reboot":
        return "__BLOCK_REBOOT__", "info"

    if cmd == "unblock-reboot":
        return "__UNBLOCK_REBOOT__", "info"

    if cmd == "block-port":
        if len(parts) < 2:
            return "Uso: block-port <puerto> [tcp|udp] [in|out]", "warn"
        try:
            port = int(parts[1])
        except ValueError:
            return f"Puerto inválido: '{parts[1]}'", "error"
        proto = parts[2].upper() if len(parts) > 2 else "TCP"
        if proto not in ("TCP", "UDP"):
            return f"Protocolo inválido: '{proto}'.", "error"
        direction = parts[3].lower() if len(parts) > 3 else "in"
        if direction not in ("in", "out"):
            return f"Dirección inválida: '{direction}'.", "error"
        ok, msg, name = cmd_block_port(port, proto, direction)
        if ok:
            if msg == "ya existe":
                return f"ℹ️  Puerto {port}/{proto} ({direction}) ya estaba bloqueado.\n    Regla: {name}", "warn"
            return f"✅  Puerto {port}/{proto} bloqueado ({direction}).\n    Regla: {name}", "ok"
        return f"❌  Error al bloquear puerto {port}:\n{msg}", "error"

    if cmd == "unblock-port":
        if len(parts) < 2:
            return "Uso: unblock-port <puerto> [tcp|udp] [in|out]", "warn"
        try:
            port = int(parts[1])
        except ValueError:
            return f"Puerto inválido: '{parts[1]}'", "error"
        proto = parts[2].upper() if len(parts) > 2 else "TCP"
        direction = parts[3].lower() if len(parts) > 3 else "in"
        ok, msg = cmd_unblock_port(port, proto, direction)
        if ok:
            return f"✅  Regla de bloqueo para puerto {port}/{proto} ({direction}) eliminada.", "ok"
        return f"❌  Error al desbloquear puerto {port}:\n{msg}", "error"

    if cmd == "block-app":
        if len(parts) < 2:
            return "Uso: block-app <ruta_exe>", "warn"
        path = " ".join(parts[1:])
        if not os.path.exists(path):
            return f"❌  El archivo no existe: {path}", "error"
        ok, msg = cmd_block_app(path)
        if ok:
            return f"✅  App bloqueada: {os.path.basename(path)}", "ok"
        return f"❌  Error al bloquear app:\n{msg}", "error"

    if cmd == "block-process":
        if len(parts) < 2:
            return "Uso: block-process <nombre>", "warn"
        proc = parts[1]
        ok, msg = cmd_block_process(proc)
        if ok:
            return f"✅  Proceso '{proc}' bloqueado (tráfico saliente).", "ok"
        return f"❌  Error al bloquear proceso '{proc}':\n{msg}", "error"

    if cmd == "status":
        if len(parts) < 2:
            return "Uso: status <puerto>", "warn"
        try:
            port = int(parts[1])
        except ValueError:
            return f"Puerto inválido: '{parts[1]}'", "error"
        results = []
        for proto in ("TCP", "UDP"):
            for direction in ("in", "out"):
                name = f"{RULE_PREFIX}Block_{proto}_{direction.upper()}_{port}"
                ok, out = _run([
                    "netsh", "advfirewall", "firewall", "show", "rule", f"name={name}",
                ])
                active = ok and "No rules match" not in out and name in out
                icon = "🔒 BLOQUEADO" if active else "🔓 libre"
                results.append(f"  {proto} {direction:3s}: {icon}")
        return f"Estado del puerto {port}:\n" + "\n".join(results), "info"

    return f"Comando desconocido: '{cmd}'\nEscribe 'help' para ver los comandos disponibles.", "warn"


# ─── STATE COLORS ─────────────────────────────────────────────────────────────

STATE_COLORS = {
    "ESTABLISHED":  "#4caf80",
    "LISTENING":    "#4da6ff",
    "TIME_WAIT":    "#f5a623",
    "CLOSE_WAIT":   "#e05c5c",
    "SYN_SENT":     "#f5a623",
    "SYN_RECEIVED": "#f5a623",
    "—":            "#7a8099",
}


# ─── CUSTOM TAB BAR ──────────────────────────────────────────────────────────

class TabBar(tk.Frame):
    """Custom Chrome-style closeable tab bar with drag-to-reorder."""

    def __init__(self, parent, on_tab_change, on_tab_close, **kwargs):
        super().__init__(parent, bg=COLORS["bg"], **kwargs)
        self._tabs = []          # list of (tab_id, label, close_btn, frame, lbl)
        self._active_id = None
        self._on_change = on_tab_change
        self._on_close  = on_tab_close

        # Drag state
        self._drag_tab_id = None
        self._drag_start_x = 0
        self._drag_ghost = None   # Toplevel ghost window

        self._scroll_frame = tk.Frame(self, bg=COLORS["bg"])
        self._scroll_frame.pack(side="left", fill="x", expand=True)

    def add_tab(self, tab_id: str, label: str) -> bool:
        """Add tab. Returns False if already exists (then activates it)."""
        for tid, *_ in self._tabs:
            if tid == tab_id:
                self.activate(tab_id)
                return False

        frame = tk.Frame(self._scroll_frame, bg=COLORS["tab_inactive"], padx=0, pady=0)
        frame.pack(side="left", padx=(0, 1), pady=(4, 0))

        lbl = tk.Label(
            frame, text=label,
            font=("Segoe UI", 9),
            bg=COLORS["tab_inactive"], fg=COLORS["text_muted"],
            padx=10, pady=6, cursor="hand2",
        )
        lbl.pack(side="left")

        close_btn = tk.Label(
            frame, text="✕",
            font=("Segoe UI", 8),
            bg=COLORS["tab_inactive"], fg=COLORS["text_muted"],
            padx=4, pady=6, cursor="hand2",
        )
        close_btn.pack(side="left")

        # Click / hover / drag bindings
        for widget in (frame, lbl):
            widget.bind("<Enter>",           lambda e, f=frame, tid=tab_id: self._hover(f, tid, True))
            widget.bind("<Leave>",           lambda e, f=frame, tid=tab_id: self._hover(f, tid, False))
            widget.bind("<ButtonPress-1>",   lambda e, tid=tab_id: self._drag_start(e, tid))
            widget.bind("<B1-Motion>",       self._drag_motion)
            widget.bind("<ButtonRelease-1>", lambda e, tid=tab_id: self._drag_release(e, tid))

        close_btn.bind("<Button-1>",  lambda e, tid=tab_id: self._close(tid))
        close_btn.bind("<Enter>",     lambda e, cb=close_btn: cb.config(fg=COLORS["danger"]))
        close_btn.bind("<Leave>",     lambda e, cb=close_btn, tid=tab_id: cb.config(
            fg=COLORS["text"] if tid == self._active_id else COLORS["text_muted"]))

        self._tabs.append((tab_id, label, close_btn, frame, lbl))
        self.activate(tab_id)
        return True

    # ── Drag-to-reorder ──────────────────────────────────────────────────

    def _drag_start(self, event, tab_id):
        self._drag_tab_id = tab_id
        self._drag_start_x = event.x_root
        self._did_drag = False

    def _drag_motion(self, event):
        if self._drag_tab_id is None:
            return
        dx = event.x_root - self._drag_start_x
        if abs(dx) < 6:
            return  # Dead zone — no drag yet
        self._did_drag = True
        src_idx = next((i for i, (tid, *_) in enumerate(self._tabs) if tid == self._drag_tab_id), None)
        if src_idx is None:
            return
        for i, (tid, label, close_btn, frame, lbl) in enumerate(self._tabs):
            fx = frame.winfo_rootx()
            fw = frame.winfo_width()
            if fx <= event.x_root <= fx + fw and i != src_idx:
                self._tabs[src_idx], self._tabs[i] = self._tabs[i], self._tabs[src_idx]
                for _, _, _, f, _ in self._tabs:
                    f.pack_forget()
                for _, _, _, f, _ in self._tabs:
                    f.pack(side="left", padx=(0, 1), pady=(4, 0))
                self._drag_start_x = event.x_root
                break

    def _drag_release(self, event, tab_id):
        """On release: if we didn't drag, treat it as a click → activate."""
        dragged = getattr(self, "_did_drag", False)
        self._drag_tab_id = None
        self._did_drag = False
        if not dragged:
            self.activate(tab_id)

    def _hover(self, frame, tab_id, entering):
        if tab_id == self._active_id:
            return
        bg = COLORS["tab_hover"] if entering else COLORS["tab_inactive"]
        frame.config(bg=bg)
        for w in frame.winfo_children():
            w.config(bg=bg)

    def _close(self, tab_id):
        self._on_close(tab_id)

    def remove_tab(self, tab_id: str):
        idx = None
        for i, (tid, *rest) in enumerate(self._tabs):
            if tid == tab_id:
                idx = i
                frame = rest[2]
                frame.destroy()
                break
        if idx is None:
            return
        self._tabs.pop(idx)

        # Activate neighbor tab
        if self._active_id == tab_id:
            self._active_id = None
            if self._tabs:
                new_idx = min(idx, len(self._tabs) - 1)
                self._on_change(self._tabs[new_idx][0])
                self.activate(self._tabs[new_idx][0])

    def activate(self, tab_id: str):
        self._active_id = tab_id
        for tid, label, close_btn, frame, lbl in self._tabs:
            if tid == tab_id:
                frame.config(bg=COLORS["tab_active"])
                lbl.config(bg=COLORS["tab_active"], fg=COLORS["accent"])
                close_btn.config(bg=COLORS["tab_active"], fg=COLORS["text_muted"])
            else:
                frame.config(bg=COLORS["tab_inactive"])
                lbl.config(bg=COLORS["tab_inactive"], fg=COLORS["text_muted"])
                close_btn.config(bg=COLORS["tab_inactive"], fg=COLORS["text_muted"])
        self._on_change(tab_id)

    def get_active(self) -> str | None:
        return self._active_id


# ─── REQUESTS TAB ─────────────────────────────────────────────────────────────

class RequestsTab(tk.Frame):
    """
    Visual network requests panel.
    Shows: [App icon] ──────────── [PC name]
    With <> animation when packets flow.
    """

    APP_ICONS = ["📦", "🔵", "🟢", "🟡", "🟠", "🔴", "⚙️", "🛠️", "📡", "💻", "🖥️", "🌐"]

    def __init__(self, parent, app):
        super().__init__(parent, bg=COLORS["bg"])
        self._app = app
        self._running = False
        self._thread = None
        self._connections_data = []
        self._packet_state = {}   # process -> packet animation tick
        self._hostname = socket.gethostname()
        self._icon_map = {}

        self._build_ui()
        self.start_monitoring()

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=COLORS["surface"], pady=8, padx=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text="📡  PETICIONES DE RED EN VIVO",
                 font=FONTS["label"], bg=COLORS["surface"], fg=COLORS["accent"]).pack(side="left")

        tk.Label(hdr,
                 text="Aplicaciones con conexiones de red activas",
                 font=FONTS["small"], bg=COLORS["surface"], fg=COLORS["text_muted"]).pack(side="left", padx=10)

        self._count_lbl = tk.Label(hdr, text="",
                                   font=FONTS["small"], bg=COLORS["surface"], fg=COLORS["text_muted"])
        self._count_lbl.pack(side="right", padx=10)

        btn_frame = tk.Frame(hdr, bg=COLORS["surface"])
        btn_frame.pack(side="right")

        tk.Button(
            btn_frame, text="↺ Actualizar",
            command=self._refresh,
            bg=COLORS["btn"], fg=COLORS["text_muted"],
            font=FONTS["small"], relief="flat", cursor="hand2",
            padx=8, pady=3, activebackground=COLORS["btn_hover"],
        ).pack(side="right", padx=(0, 6))

        self._live_var = tk.BooleanVar(value=True)
        self._live_btn = tk.Button(
            btn_frame, text="⏸ Pausar",
            command=self._toggle_live,
            bg="#2a5c2a", fg="#55dd55",
            font=FONTS["small"], relief="flat", cursor="hand2",
            padx=8, pady=3,
        )
        self._live_btn.pack(side="right", padx=(0, 6))

        # Scrollable canvas for cards
        outer = tk.Frame(self, bg=COLORS["bg"])
        outer.pack(fill="both", expand=True)

        self._canvas = tk.Canvas(outer, bg=COLORS["bg"], highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self._cards_frame = tk.Frame(self._canvas, bg=COLORS["bg"])
        self._canvas_window = self._canvas.create_window((0, 0), window=self._cards_frame, anchor="nw")
        self._cards_frame.bind("<Configure>", lambda e: self._canvas.configure(
            scrollregion=self._canvas.bbox("all")
        ))
        self._canvas.bind("<Configure>", lambda e: self._canvas.itemconfig(
            self._canvas_window, width=e.width
        ))
        self._canvas.bind("<MouseWheel>", lambda e: self._canvas.yview_scroll(-1 * int(e.delta / 120), "units"))

    def _get_icon(self, proc_name: str) -> str:
        if proc_name not in self._icon_map:
            idx = len(self._icon_map) % len(self.APP_ICONS)
            self._icon_map[proc_name] = self.APP_ICONS[idx]
        return self._icon_map[proc_name]

    def _make_pipe_animation(self, proc: str, conn_count: int) -> str:
        """Generate animated pipe string."""
        tick = self._packet_state.get(proc, 0)
        has_traffic = conn_count > 0

        # Total pipe length based on connections (5 to 30 chars)
        pipe_len = min(5 + conn_count * 2, 30)

        if not has_traffic:
            return "─" * pipe_len

        # Packet size indicator
        if conn_count >= 10:
            packet = "<///>"
        elif conn_count >= 5:
            packet = "</>"
        elif conn_count >= 2:
            packet = "<>"
        else:
            packet = "·"

        # Animate position
        pos = tick % (pipe_len + len(packet))
        left  = max(0, pos - len(packet))
        right = max(0, pipe_len - pos)

        pipe = "─" * left + packet + "─" * right
        pipe = pipe[:pipe_len]

        return pipe

    def _refresh(self):
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def _do_refresh(self):
        data = get_active_connections_for_requests()
        self.after(0, lambda: self._render(data))

    def _render(self, data: list[dict]):
        self._connections_data = data

        # Clear cards
        for w in self._cards_frame.winfo_children():
            w.destroy()

        if not data:
            tk.Label(
                self._cards_frame,
                text="No hay aplicaciones con conexiones de red activas.",
                font=FONTS["body"],
                bg=COLORS["bg"], fg=COLORS["text_muted"],
                pady=40,
            ).pack()
            self._count_lbl.config(text="0 aplicaciones")
            return

        self._count_lbl.config(text=f"{len(data)} aplicación(es)")

        for entry in data:
            self._build_card(entry)

    def _build_card(self, entry: dict):
        proc = entry["process"]
        icon = self._get_icon(proc)
        conn_count = entry["conn_count"]
        connections = entry["connections"]
        hostname = self._hostname

        # Update packet tick
        self._packet_state[proc] = self._packet_state.get(proc, 0) + 1

        card = tk.Frame(self._cards_frame, bg=COLORS["surface"], pady=0)
        card.pack(fill="x", padx=12, pady=(6, 0))

        # ── Main visual row ──────────────────────────────────────────────
        main_row = tk.Frame(card, bg=COLORS["surface"], pady=8, padx=12)
        main_row.pack(fill="x")

        # App side
        app_frame = tk.Frame(main_row, bg=COLORS["surface"])
        app_frame.pack(side="left")

        tk.Label(
            app_frame, text=icon,
            font=("Segoe UI", 20),
            bg=COLORS["surface"], fg=COLORS["text"],
        ).pack(side="left")

        tk.Label(
            app_frame, text=proc,
            font=("Segoe UI", 9, "bold"),
            bg=COLORS["surface"], fg=COLORS["text"],
            padx=6,
        ).pack(side="left")

        tk.Label(
            app_frame, text=f"PID {entry['pid']}",
            font=FONTS["small"],
            bg=COLORS["surface"], fg=COLORS["text_muted"],
        ).pack(side="left")

        # Animated pipe
        pipe_str = self._make_pipe_animation(proc, conn_count)
        pipe_color = COLORS["accent"] if conn_count > 0 else COLORS["border"]

        pipe_lbl = tk.Label(
            main_row, text=pipe_str,
            font=("Consolas", 11),
            bg=COLORS["surface"], fg=pipe_color,
            padx=8,
        )
        pipe_lbl.pack(side="left", fill="x", expand=True)

        # PC/hostname side
        pc_frame = tk.Frame(main_row, bg=COLORS["surface"])
        pc_frame.pack(side="right")

        tk.Label(
            pc_frame, text="🖥️",
            font=("Segoe UI", 18),
            bg=COLORS["surface"], fg=COLORS["text"],
        ).pack(side="left")

        tk.Label(
            pc_frame, text=hostname,
            font=("Segoe UI", 9, "bold"),
            bg=COLORS["surface"], fg=COLORS["text"],
            padx=6,
        ).pack(side="left")

        # ── Connection details ───────────────────────────────────────────
        detail_frame = tk.Frame(card, bg=COLORS["surface2"], padx=12, pady=6)
        detail_frame.pack(fill="x")

        # Show first 5 connections
        for conn in connections[:5]:
            conn_row = tk.Frame(detail_frame, bg=COLORS["surface2"])
            conn_row.pack(fill="x", pady=1)

            state = conn.get("state", "—")
            state_color = STATE_COLORS.get(state, COLORS["text_muted"])

            tk.Label(
                conn_row,
                text=f"{conn['proto']:4s}  {conn['local_addr']}:{conn['local_port']}  →  {conn['remote_addr']}:{conn['remote_port']}",
                font=FONTS["mono"],
                bg=COLORS["surface2"], fg=COLORS["console_text"],
            ).pack(side="left")

            tk.Label(
                conn_row, text=state,
                font=FONTS["mono"],
                bg=COLORS["surface2"], fg=state_color,
                padx=8,
            ).pack(side="left")

        if len(connections) > 5:
            tk.Label(
                detail_frame,
                text=f"  ... y {len(connections) - 5} conexión(es) más",
                font=FONTS["small"],
                bg=COLORS["surface2"], fg=COLORS["text_muted"],
            ).pack(anchor="w")

        # ── Block button row ─────────────────────────────────────────────
        action_row = tk.Frame(card, bg=COLORS["surface"], pady=4, padx=12)
        action_row.pack(fill="x")

        tk.Button(
            action_row,
            text="🔒 Bloquear aplicación",
            command=lambda p=proc: self._block_app(p),
            bg=COLORS["red_btn"], fg="#ffffff",
            font=("Segoe UI", 8, "bold"), relief="flat", cursor="hand2",
            padx=8, pady=3, activebackground=COLORS["red_active"],
        ).pack(side="left")

        tk.Label(
            action_row,
            text=f"  {conn_count} conexión(es) activa(s)",
            font=FONTS["small"],
            bg=COLORS["surface"], fg=COLORS["text_muted"],
        ).pack(side="left", padx=8)

        # Separator
        tk.Frame(self._cards_frame, bg=COLORS["border"], height=1).pack(fill="x", padx=12)

    def _block_app(self, proc_name: str):
        if messagebox.askyesno(
            "Bloquear aplicación",
            f"¿Bloquear todo el tráfico saliente de '{proc_name}'?\n\n"
            "Se añadirá una regla al Firewall de Windows.",
            parent=self._app,
        ):
            def run():
                ok, msg = cmd_block_app_by_name(proc_name)
                def done():
                    if ok:
                        messagebox.showinfo("Bloqueado", f"✅ '{proc_name}' bloqueado correctamente.", parent=self._app)
                    else:
                        messagebox.showerror("Error", f"No se pudo bloquear '{proc_name}':\n{msg}", parent=self._app)
                self.after(0, done)
            threading.Thread(target=run, daemon=True).start()

    def _toggle_live(self):
        if self._running:
            self.stop_monitoring()
            self._live_btn.config(text="⏵ Live", bg=COLORS["btn"], fg=COLORS["text_muted"])
        else:
            self.start_monitoring()
            self._live_btn.config(text="⏸ Pausar", bg="#2a5c2a", fg="#55dd55")

    def start_monitoring(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop_monitoring(self):
        self._running = False

    def _loop(self):
        while self._running:
            data = get_active_connections_for_requests()
            self.after(0, lambda d=data: self._render(d))
            time.sleep(3)

    def destroy(self):
        self.stop_monitoring()
        super().destroy()


# ─── MAIN APPLICATION ─────────────────────────────────────────────────────────

class FyreWallApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FyreWall — Firewall, Monitor & Bloqueo de Aula")
        self.geometry("1180x780")
        self.minsize(900, 600)
        self.configure(bg=COLORS["bg"])

        self._admin = _is_admin()
        self._connections: list[dict] = []
        self._monitor_running = False
        self._monitor_thread = None
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *a: self._apply_filter())
        self._proto_filter = tk.StringVar(value="ALL")
        self._proto_filter.trace_add("write", lambda *a: self._apply_filter())
        self._status_text = tk.StringVar(value="Listo")
        self._console_history: list[str] = []
        self._history_idx = -1

        self._insight_blocked = False
        self._rr_blocked = False
        self._fake_image: ImageTk.PhotoImage | None = None
        self._fake_image_path: str = ""
        self._autocomplete_popup: tk.Toplevel | None = None

        # Tab content frames
        self._tab_frames: dict[str, tk.Frame] = {}
        self._current_tab: str | None = None

        self._apply_theme()
        self._build_ui()
        self._center()
        self.after(200, self._boot)

    # ── Theme ──────────────────────────────────────────────────────────────

    def _apply_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TScrollbar",
                        background=COLORS["surface2"],
                        troughcolor=COLORS["bg"],
                        arrowcolor=COLORS["text_muted"],
                        borderwidth=0, relief="flat")
        style.configure("Treeview",
                        background=COLORS["surface"],
                        foreground=COLORS["text"],
                        fieldbackground=COLORS["surface"],
                        borderwidth=0, rowheight=22,
                        font=FONTS["mono"])
        style.configure("Treeview.Heading",
                        background=COLORS["surface2"],
                        foreground=COLORS["text_muted"],
                        borderwidth=0, font=FONTS["label"])
        style.map("Treeview",
                  background=[("selected", COLORS["accent"])],
                  foreground=[("selected", "#000000")])

    # ── Layout ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Top bar ────────────────────────────────────────────────────────
        topbar = tk.Frame(self, bg=COLORS["surface"], height=52)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        tk.Label(topbar, text="🔥 FyreWall",
                 font=FONTS["title"],
                 bg=COLORS["surface"], fg=COLORS["accent"]).pack(side="left", padx=20, pady=8)

        tk.Label(topbar, text="Monitor  •  Firewall  •  Anti-Vigilancia",
                 font=FONTS["subtitle"],
                 bg=COLORS["surface"], fg=COLORS["text_muted"]).pack(side="left", padx=4)

        if self._admin:
            badge_col, badge_txt = "#2a5c2a", "  ✅ ADMIN  "
        else:
            badge_col, badge_txt = "#5a1a1a", "  ⚠️ Sin privilegios  "

        tk.Label(topbar, text=badge_txt,
                 font=("Segoe UI", 8, "bold"),
                 bg=badge_col, fg="#ffffff",
                 padx=6, pady=3).pack(side="right", padx=16, pady=10)

        # ── Tab strip + open buttons ────────────────────────────────────────
        tab_strip = tk.Frame(self, bg=COLORS["bg"])
        tab_strip.pack(fill="x", side="top")

        self._tab_bar = TabBar(
            tab_strip,
            on_tab_change=self._on_tab_change,
            on_tab_close=self._on_tab_close,
        )
        self._tab_bar.pack(side="left", fill="x", expand=True)

        # Open-tab buttons
        btn_area = tk.Frame(tab_strip, bg=COLORS["bg"])
        btn_area.pack(side="right", padx=6, pady=2)

        open_tabs = [
            ("⌨️", "terminal", "Terminal"),
            ("🔍", "monitor", "Monitor"),
            ("🏫", "aula", "Aula"),
            ("📡", "peticiones", "Peticiones"),
        ]
        for icon, tid, label in open_tabs:
            tk.Button(
                btn_area,
                text=f"{icon} {label}",
                command=lambda t=tid, l=label, i=icon: self._open_tab(t, f"{i} {l}"),
                bg=COLORS["surface2"], fg=COLORS["text_muted"],
                font=("Segoe UI", 8), relief="flat", cursor="hand2",
                padx=6, pady=2,
                activebackground=COLORS["btn_hover"],
                activeforeground=COLORS["text"],
            ).pack(side="left", padx=(2, 0))

        # Thin separator under tab bar
        tk.Frame(self, bg=COLORS["border"], height=1).pack(fill="x")

        # ── Content area ────────────────────────────────────────────────────
        self._content = tk.Frame(self, bg=COLORS["bg"])
        self._content.pack(fill="both", expand=True)

        # Pre-build tab content
        self._build_terminal_tab()
        self._build_debug_tab()
        self._build_classroom_tab()
        # Peticiones is built on demand

        self._build_status_bar()

    # ── Tab management ─────────────────────────────────────────────────────

    def _open_tab(self, tab_id: str, label: str):
        """Open a tab or activate if already open."""
        if tab_id == "peticiones" and tab_id not in self._tab_frames:
            frame = RequestsTab(self._content, self)
            self._tab_frames[tab_id] = frame

        self._tab_bar.add_tab(tab_id, label)

    def _on_tab_change(self, tab_id: str):
        self._current_tab = tab_id
        for tid, frame in self._tab_frames.items():
            if tid == tab_id:
                frame.place(relx=0, rely=0, relwidth=1, relheight=1)
                frame.lift()
            else:
                frame.place_forget()
        # Hide empty-state if any tab is active
        if hasattr(self, "_empty_state"):
            self._empty_state.place_forget()

    def _show_empty_state(self):
        """Show the 'open a terminal' placeholder when no tabs are open."""
        if not hasattr(self, "_empty_state"):
            self._empty_state = tk.Frame(self._content, bg=COLORS["bg"])
            tk.Label(
                self._empty_state,
                text="⌨️",
                font=("Segoe UI", 48),
                bg=COLORS["bg"], fg=COLORS["border"],
            ).pack(pady=(0, 8))
            tk.Label(
                self._empty_state,
                text="Abrir una terminal",
                font=("Segoe UI", 16),
                bg=COLORS["bg"], fg=COLORS["text_muted"],
                cursor="hand2",
            ).pack()
            tk.Label(
                self._empty_state,
                text="Haz clic en ⌨️ Terminal en la barra superior",
                font=("Segoe UI", 10),
                bg=COLORS["bg"], fg=COLORS["border"],
            ).pack(pady=(4, 0))
            self._empty_state.bind("<Button-1>", lambda e: self._open_tab("terminal", "⌨️ Terminal"))
            for w in self._empty_state.winfo_children():
                w.bind("<Button-1>", lambda e: self._open_tab("terminal", "⌨️ Terminal"))
        self._empty_state.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._empty_state.lift()

    def _on_tab_close(self, tab_id: str):
        if tab_id == "peticiones" and tab_id in self._tab_frames:
            self._tab_frames[tab_id].destroy()
            del self._tab_frames[tab_id]
        elif tab_id == "batch" and tab_id in self._tab_frames:
            self._tab_frames[tab_id].destroy()
            del self._tab_frames[tab_id]
        self._tab_bar.remove_tab(tab_id)
        # If no tabs remain, show empty state
        if not self._tab_bar._tabs:
            self._show_empty_state()

    # ── Terminal Tab ───────────────────────────────────────────────────────

    def _build_terminal_tab(self):
        frame = tk.Frame(self._content, bg=COLORS["bg"])
        self._tab_frames["terminal"] = frame
        self._build_console_tab(frame)

    # ── Debug Monitor Tab ──────────────────────────────────────────────────

    def _build_debug_tab(self):
        frame = tk.Frame(self._content, bg=COLORS["bg"])
        self._tab_frames["monitor"] = frame

        toolbar = tk.Frame(frame, bg=COLORS["surface"], pady=8, padx=12)
        toolbar.pack(fill="x")

        tk.Label(toolbar, text="CONEXIONES ACTIVAS",
                 font=FONTS["label"],
                 bg=COLORS["surface"], fg=COLORS["accent"]).pack(side="left")

        ctrl = tk.Frame(toolbar, bg=COLORS["surface"])
        ctrl.pack(side="right")

        self._live_var = tk.BooleanVar(value=False)
        self._live_btn = tk.Button(
            ctrl, text="⏵  LIVE",
            command=self._toggle_live,
            bg=COLORS["btn"], fg=COLORS["text_muted"],
            font=FONTS["small"], relief="flat", cursor="hand2",
            padx=10, pady=4,
            activebackground=COLORS["btn_hover"],
        )
        self._live_btn.pack(side="right", padx=(6, 0))

        tk.Button(
            ctrl, text="↺  Actualizar",
            command=self._refresh_connections,
            bg=COLORS["btn"], fg=COLORS["text_muted"],
            font=FONTS["small"], relief="flat", cursor="hand2",
            padx=10, pady=4,
            activebackground=COLORS["btn_hover"],
        ).pack(side="right", padx=(6, 0))

        self._block_sel_btn = tk.Button(
            ctrl, text="🔒  Bloquear Puerto Seleccionado",
            command=self._block_selected,
            bg="#2a1a10", fg="#f5a623",
            font=FONTS["small"], relief="flat", cursor="hand2",
            padx=10, pady=4,
            activebackground="#3a2a18",
        )
        self._block_sel_btn.pack(side="right", padx=(6, 0))

        fbar = tk.Frame(frame, bg=COLORS["bg"], pady=6, padx=12)
        fbar.pack(fill="x")

        tk.Label(fbar, text="Filtrar:",
                 font=FONTS["small"], bg=COLORS["bg"], fg=COLORS["text_muted"]).pack(side="left")

        filter_entry = tk.Entry(
            fbar, textvariable=self._filter_var,
            bg=COLORS["surface"], fg=COLORS["text"],
            font=FONTS["mono"], relief="flat", bd=0,
            insertbackground=COLORS["accent"],
            width=30,
        )
        filter_entry.pack(side="left", padx=(6, 12), ipady=5)

        tk.Label(fbar, text="Protocolo:",
                 font=FONTS["small"], bg=COLORS["bg"], fg=COLORS["text_muted"]).pack(side="left")

        for proto in ("ALL", "TCP", "UDP"):
            tk.Radiobutton(
                fbar, text=proto,
                variable=self._proto_filter, value=proto,
                bg=COLORS["bg"], fg=COLORS["text_muted"],
                activebackground=COLORS["bg"], activeforeground=COLORS["accent"],
                selectcolor=COLORS["bg"],
                font=FONTS["small"], cursor="hand2",
            ).pack(side="left", padx=4)

        self._conn_count_lbl = tk.Label(
            fbar, text="",
            font=FONTS["small"], bg=COLORS["bg"], fg=COLORS["text_muted"],
        )
        self._conn_count_lbl.pack(side="right")

        tree_frame = tk.Frame(frame, bg=COLORS["bg"])
        tree_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        columns = ("process", "pid", "proto", "local_port", "local_addr",
                   "remote_addr", "remote_port", "state")
        col_labels = {
            "process":     "Proceso / App",
            "pid":         "PID",
            "proto":       "Proto",
            "local_port":  "Puerto Local",
            "local_addr":  "IP Local",
            "remote_addr": "IP Remota",
            "remote_port": "Puerto Remoto",
            "state":       "Estado",
        }
        col_widths = {
            "process": 200, "pid": 60, "proto": 50,
            "local_port": 90, "local_addr": 110,
            "remote_addr": 130, "remote_port": 90, "state": 100,
        }

        self._tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")
        for col in columns:
            self._tree.heading(col, text=col_labels[col], command=lambda c=col: self._sort_tree(c))
            self._tree.column(col, width=col_widths[col], minwidth=40)

        for state, color in STATE_COLORS.items():
            self._tree.tag_configure(f"state_{state}", foreground=color)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal",  command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self._ctx_menu = tk.Menu(self, tearoff=0,
                                 bg=COLORS["surface2"], fg=COLORS["text"],
                                 activebackground=COLORS["accent"], activeforeground="#000")
        self._ctx_menu.add_command(label="🔒 Bloquear puerto local",    command=self._ctx_block_port)
        self._ctx_menu.add_command(label="🛡️ Bloquear proceso",         command=self._ctx_block_process)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="📋 Copiar línea",             command=self._ctx_copy)
        self._tree.bind("<Button-3>", self._show_ctx_menu)

        self._sort_col  = "local_port"
        self._sort_rev  = False
        self._all_rows: list[dict] = []

    # ── Console Tab ───────────────────────────────────────────────────────

    def _build_console_tab(self, parent):
        hdr = tk.Frame(parent, bg=COLORS["surface"], pady=8, padx=12)
        hdr.pack(fill="x")

        tk.Label(hdr, text="CONSOLA FYREWALL",
                 font=FONTS["label"],
                 bg=COLORS["surface"], fg=COLORS["accent"]).pack(side="left")

        tk.Button(
            hdr, text="🗑  Limpiar",
            command=self._clear_console,
            bg=COLORS["btn"], fg=COLORS["text_muted"],
            font=FONTS["small"], relief="flat", cursor="hand2",
            padx=8, pady=3, activebackground=COLORS["btn_hover"],
        ).pack(side="right")

        tk.Button(
            hdr, text="❓  Ayuda",
            command=lambda: self._exec_console("help"),
            bg=COLORS["btn"], fg=COLORS["accent"],
            font=FONTS["small"], relief="flat", cursor="hand2",
            padx=8, pady=3, activebackground=COLORS["btn_hover"],
        ).pack(side="right", padx=(0, 6))

        out_frame = tk.Frame(parent, bg=COLORS["console_bg"])
        out_frame.pack(fill="both", expand=True, padx=12, pady=(8, 0))

        self._console_out = tk.Text(
            out_frame,
            bg=COLORS["console_bg"], fg=COLORS["console_text"],
            font=FONTS["mono_lg"], relief="flat", bd=0,
            state="disabled", wrap="word", padx=12, pady=10, cursor="arrow",
        )
        console_sb = ttk.Scrollbar(out_frame, orient="vertical", command=self._console_out.yview)
        self._console_out.configure(yscrollcommand=console_sb.set)
        console_sb.pack(side="right", fill="y")
        self._console_out.pack(side="left", fill="both", expand=True)

        self._console_out.tag_configure("prompt",  foreground=COLORS["console_prompt"], font=("Consolas", 10, "bold"))
        self._console_out.tag_configure("ok",       foreground=COLORS["console_ok"])
        self._console_out.tag_configure("error",    foreground=COLORS["console_err"])
        self._console_out.tag_configure("warn",     foreground=COLORS["console_warn"])
        self._console_out.tag_configure("info",     foreground=COLORS["console_text"])
        self._console_out.tag_configure("muted",    foreground=COLORS["console_info"])
        self._console_out.tag_configure("header",   foreground=COLORS["accent"], font=("Consolas", 10, "bold"))

        input_frame = tk.Frame(parent, bg=COLORS["console_bg"], pady=6, padx=12)
        input_frame.pack(fill="x", padx=12, pady=(0, 8))

        tk.Label(input_frame, text="❯",
                 font=("Consolas", 12, "bold"),
                 bg=COLORS["console_bg"], fg=COLORS["console_prompt"]).pack(side="left", padx=(0, 8))

        self._input_var = tk.StringVar()
        self._input_entry = tk.Entry(
            input_frame,
            textvariable=self._input_var,
            bg=COLORS["console_bg"], fg=COLORS["console_text"],
            font=FONTS["mono_lg"], relief="flat", bd=0,
            insertbackground=COLORS["console_prompt"],
        )
        self._input_entry.pack(side="left", fill="x", expand=True, ipady=4)
        self._input_entry.bind("<Return>",     self._on_console_enter)
        self._input_entry.bind("<Up>",         self._history_up)
        self._input_entry.bind("<Down>",       self._history_down)
        self._input_entry.bind("<Tab>",        self._autocomplete_tab)
        self._input_entry.bind("<KeyRelease>", self._on_key_release)
        self._input_entry.bind("<FocusOut>",   self._hide_autocomplete)
        self._input_entry.bind("<Escape>",     self._hide_autocomplete)
        self._input_entry.focus_set()

        tk.Button(
            input_frame, text="Ejecutar",
            command=lambda: self._on_console_enter(None),
            bg=COLORS["accent"], fg="#000000",
            font=FONTS["button"], relief="flat", cursor="hand2",
            padx=14, pady=4, activebackground=COLORS["accent_hover"],
        ).pack(side="right")

    # ── Classroom Tab ─────────────────────────────────────────────────────

    def _build_classroom_tab(self):
        frame = tk.Frame(self._content, bg=COLORS["bg"])
        self._tab_frames["aula"] = frame

        hdr = tk.Frame(frame, bg=COLORS["surface"], pady=10, padx=16)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🏫  MODO BLOQUEO DE AULA",
                 font=FONTS["title"],
                 bg=COLORS["surface"], fg=COLORS["accent"]).pack(side="left")
        tk.Label(hdr,
                 text="Bloquea Faronics Insight Student y Reboot Restore Enterprise",
                 font=FONTS["small"],
                 bg=COLORS["surface"], fg=COLORS["text_muted"]).pack(side="left", padx=12)

        # ── Service status banner ──────────────────────────────────────────
        self._service_banner = tk.Frame(frame, bg=COLORS["surface2"], pady=8, padx=14)
        self._service_banner.pack(fill="x", padx=10, pady=(8, 0))

        self._insight_svc_lbl = tk.Label(
            self._service_banner,
            text="🔍 Comprobando Insight...",
            font=("Segoe UI", 9),
            bg=COLORS["surface2"], fg=COLORS["text_muted"],
        )
        self._insight_svc_lbl.pack(side="left", padx=(0, 20))

        self._rr_svc_lbl = tk.Label(
            self._service_banner,
            text="🔍 Comprobando Reboot Restore...",
            font=("Segoe UI", 9),
            bg=COLORS["surface2"], fg=COLORS["text_muted"],
        )
        self._rr_svc_lbl.pack(side="left")

        tk.Button(
            self._service_banner, text="↺ Actualizar estado",
            command=self._check_services_async,
            bg=COLORS["btn"], fg=COLORS["text_muted"],
            font=("Segoe UI", 8), relief="flat", cursor="hand2",
            padx=6, pady=2, activebackground=COLORS["btn_hover"],
        ).pack(side="right")

        # Main content: two columns
        content = tk.Frame(frame, bg=COLORS["bg"])
        content.pack(fill="both", expand=True, padx=10, pady=8)

        left  = tk.Frame(content, bg=COLORS["bg"])
        right = tk.Frame(content, bg=COLORS["bg"])
        left.pack(side="left", fill="both", expand=True, padx=(0, 5))
        right.pack(side="right", fill="both", expand=True, padx=(5, 0))

        self._build_app_block_card(
            left, "insight",
            "🎓  Faronics Insight Student",
            "Software de vigilancia de aula. Permite al profesor ver la pantalla de cada alumno "
            "en tiempo real, tomar el control del ratón/teclado, bloquear aplicaciones y capturar "
            "screenshots.",
            ["UDP/TCP 796 (legacy)", "UDP/TCP 11796 (moderno)", "UDP 1053 (status broadcast)",
             "TCP 8888/8889/8890 (WebSocket v11)", "TCP 10000-20000 (control remoto)"],
            "#1a2a3a",
        )

        self._build_app_block_card(
            left, "rebootrestore",
            "🔄  Reboot Restore Enterprise",
            "Gestión centralizada de PCs. El servidor puede ver qué hace cada cliente, "
            "aplicar configuraciones remotamente y hacer remote control via VNC integrado.",
            ["TCP 9000 (Endpoint Manager, configurable)", "TCP 5900 (VNC / remote control)",
             "TCP 9001, 9010 (puertos alternativos)"],
            "#1a2a1a",
        )

        # Right: log
        log_hdr = tk.Frame(right, bg=COLORS["surface"], pady=6, padx=10)
        log_hdr.pack(fill="x")
        tk.Label(log_hdr, text="REGISTRO DE OPERACIONES",
                 font=FONTS["label"], bg=COLORS["surface"], fg=COLORS["accent"]).pack(side="left")
        tk.Button(
            log_hdr, text="🗑 Limpiar",
            command=self._clear_classroom_log,
            bg=COLORS["btn"], fg=COLORS["text_muted"],
            font=("Segoe UI", 8), relief="flat", cursor="hand2",
            padx=6, pady=2, activebackground=COLORS["btn_hover"],
        ).pack(side="right")

        log_frame = tk.Frame(right, bg=COLORS["console_bg"])
        log_frame.pack(fill="both", expand=True, pady=(0, 6))

        self._classroom_log = tk.Text(
            log_frame,
            bg=COLORS["console_bg"], fg=COLORS["console_text"],
            font=("Consolas", 8), relief="flat", bd=0,
            state="disabled", wrap="word", padx=8, pady=8,
        )
        log_sb = ttk.Scrollbar(log_frame, orient="vertical", command=self._classroom_log.yview)
        self._classroom_log.configure(yscrollcommand=log_sb.set)
        log_sb.pack(side="right", fill="y")
        self._classroom_log.pack(side="left", fill="both", expand=True)

        for tag, color in [("ok", COLORS["console_ok"]), ("error", COLORS["console_err"]),
                            ("warn", COLORS["console_warn"]), ("info", COLORS["console_text"]),
                            ("muted", COLORS["console_info"])]:
            self._classroom_log.tag_configure(tag, foreground=color)
        self._classroom_log.tag_configure("header", foreground=COLORS["accent"],
                                          font=("Consolas", 9, "bold"))

        # ── Fake preview — one per app ────────────────────────────────────
        prev_hdr = tk.Frame(right, bg=COLORS["surface"], pady=6, padx=10)
        prev_hdr.pack(fill="x")
        tk.Label(prev_hdr, text="🖥️  PREVIEW FALSA (trampa visual)",
                 font=FONTS["label"], bg=COLORS["surface"], fg="#f5a623").pack(side="left")

        # Container with two side-by-side fake preview panels
        fake_row = tk.Frame(right, bg=COLORS["bg"])
        fake_row.pack(fill="x", pady=(0, 4))

        self._build_fake_preview_card(
            fake_row, "insight",
            "🎓 Insight",
            "La imagen que verá el profesor\nen Faronics Insight.",
        )
        self._build_fake_preview_card(
            fake_row, "rebootrestore",
            "🔄 Reboot Restore",
            "La imagen que verá el admin\nen Reboot Restore.",
        )

    def _build_fake_preview_card(self, parent, app_key, title, hint):
        """Build a fake-preview panel for a given app."""
        card = tk.Frame(parent, bg=COLORS["surface2"], pady=6, padx=8)
        card.pack(side="left", fill="both", expand=True, padx=(0, 4) if app_key == "insight" else (4, 0))

        tk.Label(card, text=title,
                 font=("Segoe UI", 8, "bold"),
                 bg=COLORS["surface2"], fg="#f5a623").pack(anchor="w")
        tk.Label(card, text=hint,
                 font=("Segoe UI", 7),
                 bg=COLORS["surface2"], fg=COLORS["text_muted"],
                 justify="left").pack(anchor="w", pady=(0, 4))

        img_var = tk.StringVar(value="Sin imagen")
        img_canvas = tk.Label(
            card, bg="#0e1117",
            text="[ sin imagen ]",
            fg=COLORS["border"], font=("Segoe UI", 7),
            width=24, height=5,
        )
        img_canvas.pack(fill="x")

        btn_row = tk.Frame(card, bg=COLORS["surface2"])
        btn_row.pack(fill="x", pady=(4, 0))

        tk.Button(
            btn_row, text="📂 Cargar",
            command=lambda: self._load_fake_image_for(app_key, img_var, img_canvas),
            bg=COLORS["btn"], fg=COLORS["text"],
            font=("Segoe UI", 7), relief="flat", cursor="hand2",
            padx=6, pady=2, activebackground=COLORS["btn_hover"],
        ).pack(side="left")

        tk.Label(btn_row, textvariable=img_var,
                 font=("Segoe UI", 7),
                 bg=COLORS["surface2"], fg=COLORS["text_muted"]).pack(side="left", padx=6)

        # Store refs for later
        if app_key == "insight":
            self._insight_img_var = img_var
            self._insight_img_canvas = img_canvas
            self._fake_image_insight = None
        else:
            self._rr_img_var = img_var
            self._rr_img_canvas = img_canvas
            self._fake_image_rr = None

    def _load_fake_image_for(self, app_key: str, img_var: tk.StringVar, img_canvas: tk.Label):
        path = filedialog.askopenfilename(
            parent=self,
            title=f"Selecciona imagen para {app_key}",
            filetypes=[("Imágenes", "*.png *.jpg *.jpeg *.bmp *.gif"), ("Todos", "*.*")]
        )
        if not path:
            return
        try:
            img = Image.open(path)
            img.thumbnail((200, 120), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            img_canvas.config(image=photo, text="", bg=COLORS["bg"])
            img_var.set(f"✅ {os.path.basename(path)}")
            self._classroom_log_write(
                f"\n🖼️  Preview {app_key}: {os.path.basename(path)}", "ok")
            # Keep reference
            if app_key == "insight":
                self._fake_image_insight = photo
            else:
                self._fake_image_rr = photo
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cargar la imagen:\n{e}", parent=self)

    def _build_app_block_card(self, parent, app_key, title, description, ports, bg_color):
        card = tk.Frame(parent, bg=bg_color, bd=1, relief="flat")
        card.pack(fill="x", pady=(0, 10))

        title_bar = tk.Frame(card, bg=bg_color, pady=8, padx=12)
        title_bar.pack(fill="x")
        tk.Label(title_bar, text=title,
                 font=("Segoe UI", 10, "bold"),
                 bg=bg_color, fg=COLORS["text"]).pack(side="left")

        status_var = tk.StringVar(value="⬤ Libre")
        status_label = tk.Label(title_bar, textvariable=status_var,
                                font=("Segoe UI", 8, "bold"),
                                bg=bg_color, fg=COLORS["success"])
        status_label.pack(side="right")

        if app_key == "insight":
            self._insight_status_var   = status_var
            self._insight_status_label = status_label
        else:
            self._rr_status_var   = status_var
            self._rr_status_label = status_label

        desc_frame = tk.Frame(card, bg=bg_color, padx=12)
        desc_frame.pack(fill="x")
        tk.Label(desc_frame, text=description,
                 font=("Segoe UI", 8),
                 bg=bg_color, fg=COLORS["text_muted"],
                 wraplength=360, justify="left").pack(anchor="w")

        ports_frame = tk.Frame(card, bg=bg_color, padx=12, pady=4)
        ports_frame.pack(fill="x")
        tk.Label(ports_frame, text="Puertos bloqueados:",
                 font=("Segoe UI", 8, "bold"),
                 bg=bg_color, fg=COLORS["text_muted"]).pack(anchor="w")
        tk.Label(ports_frame,
                 text="  " + "  •  ".join(ports),
                 font=("Consolas", 7),
                 bg=bg_color, fg=COLORS["accent"],
                 wraplength=360, justify="left").pack(anchor="w")

        btn_frame = tk.Frame(card, bg=bg_color, padx=12, pady=8)
        btn_frame.pack(fill="x")

        tk.Button(
            btn_frame, text="🔒  BLOQUEAR TODO",
            command=lambda k=app_key: self._classroom_block_all(k),
            bg=COLORS["red_btn"], fg="#ffffff",
            font=("Segoe UI", 9, "bold"), relief="flat", cursor="hand2",
            padx=12, pady=5, activebackground=COLORS["red_active"],
        ).pack(side="left")

        tk.Button(
            btn_frame, text="🔓  Desbloquear",
            command=lambda k=app_key: self._classroom_unblock(k),
            bg=COLORS["console_ok"], fg="#ffffff",
            font=("Segoe UI", 9, "bold"), relief="flat", cursor="hand2",
            padx=10, pady=5, activebackground=COLORS["green_active"],
        ).pack(side="left", padx=(8, 0))

        tk.Button(
            btn_frame, text="⏰  Crear tarea de inicio (persistente)",
            command=lambda k=app_key: self._classroom_create_task(k),
            bg="#1a1a3a", fg="#8888ff",
            font=("Segoe UI", 8), relief="flat", cursor="hand2",
            padx=10, pady=5, activebackground="#2a2a5a",
        ).pack(side="left", padx=(8, 0))

        tk.Button(
            btn_frame, text="🛑  Deshabilitar servicios",
            command=lambda k=app_key: self._classroom_disable_services(k),
            bg="#2a1a1a", fg="#ff8888",
            font=("Segoe UI", 8), relief="flat", cursor="hand2",
            padx=10, pady=5, activebackground="#3a2a2a",
        ).pack(side="left", padx=(8, 0))

    # ── Status bar ─────────────────────────────────────────────────────────

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=COLORS["surface"], height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._status_dot = tk.Label(bar, text="●", font=("Segoe UI", 8),
                                    bg=COLORS["surface"], fg=COLORS["success"])
        self._status_dot.pack(side="left", padx=(12, 4))

        tk.Label(bar, textvariable=self._status_text,
                 font=FONTS["small"],
                 bg=COLORS["surface"], fg=COLORS["text_muted"], anchor="w").pack(side="left")

        tk.Label(bar, text="FyreWall v2.1 — Monitor + Consola + Bloqueo Aula",
                 font=FONTS["small"],
                 bg=COLORS["surface"], fg=COLORS["border"]).pack(side="right", padx=12)

        self._status_text.trace_add("write", lambda *a: self._update_status_dot())

    def _update_status_dot(self):
        t = self._status_text.get().lower()
        if "✅" in t or "ok" in t or "listo" in t:
            c = COLORS["success"]
        elif "error" in t or "❌" in t:
            c = COLORS["danger"]
        else:
            c = COLORS["accent"]
        try:
            self._status_dot.config(fg=c)
        except Exception:
            pass

    # ── Boot ───────────────────────────────────────────────────────────────

    def _boot(self):
        # Open only the terminal tab at start
        self._open_tab("terminal", "⌨️ Terminal")

        self._console_write("FyreWall v2.1 — Monitor + Consola + Bloqueo de Aula", "header")
        self._console_write("─" * 60, "muted")
        if not self._admin:
            self._console_write(
                "⚠️  Sin privilegios de Administrador — algunas operaciones fallarán.\n"
                "    Reinicia la aplicación como Administrador.",
                "warn"
            )
        else:
            self._console_write("✅  Ejecutando con privilegios de Administrador.", "ok")
        self._console_write(
            "\nEscribe 'help' para ver los comandos disponibles.\n"
            "Usa 'peticiones', 'monitor' o 'aula' para abrir más pestañas.\n",
            "muted"
        )

        # Check services in background
        self._check_services_async()

    def _check_services_async(self):
        """Check if classroom services are running and update banner."""
        def run():
            status = check_classroom_services_status()
            self.after(0, lambda: self._update_service_banners(status))
        threading.Thread(target=run, daemon=True).start()

    def _update_service_banners(self, status: dict):
        insight = status["insight"]
        rr      = status["rebootrestore"]

        # Insight
        if insight["status"] == "running":
            self._insight_svc_lbl.config(
                text=f"🔴 Insight ACTIVO ({insight['service']})",
                fg=COLORS["danger"]
            )
            self._console_write(
                f"⚠️  SERVICIO ACTIVO: Faronics Insight ({insight['service']}) está CORRIENDO.",
                "warn"
            )
            self._console_write(
                "    Usa 'block-insight' para bloquearlo, o ve a la pestaña Aula.", "muted"
            )
        elif insight["status"] == "stopped":
            self._insight_svc_lbl.config(
                text=f"🟡 Insight detenido ({insight['service']})",
                fg=COLORS["warning"]
            )
        else:
            self._insight_svc_lbl.config(
                text="✅ Insight: no detectado",
                fg=COLORS["success"]
            )

        # Reboot Restore
        if rr["status"] == "running":
            self._rr_svc_lbl.config(
                text=f"🔴 Reboot Restore ACTIVO ({rr['service']})",
                fg=COLORS["danger"]
            )
            self._console_write(
                f"⚠️  SERVICIO ACTIVO: Reboot Restore ({rr['service']}) está CORRIENDO.",
                "warn"
            )
            self._console_write(
                "    Usa 'block-reboot' para bloquearlo, o ve a la pestaña Aula.", "muted"
            )
        elif rr["status"] == "stopped":
            self._rr_svc_lbl.config(
                text=f"🟡 Reboot Restore detenido ({rr['service']})",
                fg=COLORS["warning"]
            )
        else:
            self._rr_svc_lbl.config(
                text="✅ Reboot Restore: no detectado",
                fg=COLORS["success"]
            )

    # ── Connection scanning ────────────────────────────────────────────────

    def _refresh_connections(self):
        self._status_text.set("Escaneando conexiones...")
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self):
        conns = scan_connections()
        self.after(0, lambda: self._render_connections(conns))

    def _render_connections(self, conns: list[dict]):
        self._all_rows = conns
        self._apply_filter()
        n = len(conns)
        self._status_text.set(f"✅  {n} conexión{'es' if n != 1 else ''} detectada{'s' if n != 1 else ''}")

    def _apply_filter(self):
        ftext  = self._filter_var.get().lower()
        fproto = self._proto_filter.get()

        filtered = []
        for c in self._all_rows:
            if fproto != "ALL" and c["proto"] != fproto:
                continue
            if ftext:
                haystack = (
                    f"{c['process']} {c['proto']} {c['local_port']} "
                    f"{c['remote_addr']} {c['state']}"
                ).lower()
                if ftext not in haystack:
                    continue
            filtered.append(c)

        rev = self._sort_rev
        col = self._sort_col
        try:
            if col == "local_port":
                filtered.sort(key=lambda x: x["local_port"], reverse=rev)
            else:
                filtered.sort(key=lambda x: str(x.get(col, "")), reverse=rev)
        except Exception:
            pass

        for item in self._tree.get_children():
            self._tree.delete(item)

        for c in filtered:
            state = c["state"].strip()
            color_tag = f"state_{state}" if state in STATE_COLORS else "state_—"
            self._tree.insert("", "end",
                values=(
                    c["process"], c["pid"], c["proto"],
                    c["local_port"], c["local_addr"],
                    c["remote_addr"], c["remote_port"],
                    state,
                ),
                tags=(color_tag,),
            )

        n = len(filtered)
        total = len(self._all_rows)
        suffix = f" (filtrando {total - n})" if n < total else ""
        self._conn_count_lbl.config(text=f"{n} conexiones{suffix}")

    def _sort_tree(self, col: str):
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = False
        self._apply_filter()

    # ── Live monitor ──────────────────────────────────────────────────────

    def _toggle_live(self):
        if self._monitor_running:
            self._monitor_running = False
            self._live_btn.config(text="⏵  LIVE", bg=COLORS["btn"], fg=COLORS["text_muted"])
            self._status_text.set("Monitor en vivo detenido")
        else:
            self._monitor_running = True
            self._live_btn.config(text="⏸  STOP", bg="#2a5c2a", fg="#55dd55",
                                  activebackground="#336633")
            self._status_text.set("Monitor en vivo activo — actualizando cada 3s")
            self._monitor_thread = threading.Thread(target=self._live_loop, daemon=True)
            self._monitor_thread.start()

    def _live_loop(self):
        while self._monitor_running:
            conns = scan_connections()
            self.after(0, lambda c=conns: self._render_connections(c))
            time.sleep(3)

    # ── Context menu ──────────────────────────────────────────────────────

    def _show_ctx_menu(self, event):
        row = self._tree.identify_row(event.y)
        if row:
            self._tree.selection_set(row)
            try:
                self._ctx_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self._ctx_menu.grab_release()

    def _get_selected_row(self) -> dict | None:
        sel = self._tree.selection()
        if not sel:
            return None
        vals = self._tree.item(sel[0], "values")
        if not vals:
            return None
        return {
            "process":     vals[0],
            "pid":         vals[1],
            "proto":       vals[2],
            "local_port":  vals[3],
            "local_addr":  vals[4],
            "remote_addr": vals[5],
            "remote_port": vals[6],
            "state":       vals[7],
        }

    def _block_selected(self):
        row = self._get_selected_row()
        if not row:
            messagebox.showinfo("Sin selección", "Selecciona una fila en el monitor.", parent=self)
            return
        port  = row["local_port"]
        proto = row["proto"]
        proc  = row["process"]
        if not messagebox.askyesno(
            "Bloquear puerto",
            f"¿Bloquear el puerto {port}/{proto}?\nProceso: {proc}\n\n"
            "Esto añadirá una regla de Firewall de Windows."
        ):
            return
        cmd = f"block-port {port} {proto.lower()} in"
        self._exec_console(cmd)

    def _ctx_block_port(self):
        self._block_selected()

    def _ctx_block_process(self):
        row = self._get_selected_row()
        if not row:
            return
        proc = row["process"]
        if messagebox.askyesno("Bloquear proceso",
                               f"¿Bloquear el tráfico saliente de '{proc}'?"):
            self._exec_console(f"block-process {proc}")

    def _ctx_copy(self):
        row = self._get_selected_row()
        if not row:
            return
        line = "  ".join(str(v) for v in row.values())
        self.clipboard_clear()
        self.clipboard_append(line)

    # ── Console ───────────────────────────────────────────────────────────

    def _on_console_enter(self, event):
        cmd = self._input_var.get().strip()
        if not cmd:
            return
        self._hide_autocomplete()
        self._input_var.set("")
        self._console_history.insert(0, cmd)
        self._history_idx = -1

        self._console_write(f"\n❯ {cmd}", "prompt")
        self._status_text.set(f"Ejecutando: {cmd}")

        threading.Thread(target=self._run_console_cmd, args=(cmd,), daemon=True).start()

    def _run_console_cmd(self, cmd: str):
        output, level = parse_and_run(cmd)
        self.after(0, lambda: self._handle_console_result(output, level))

    def _handle_console_result(self, output: str, level: str):
        if output == "__CLEAR__":
            self._clear_console()
            return
        if output == "__SCAN__":
            self._refresh_connections()
            self._console_write("↺  Re-escaneando conexiones...", "muted")
            return
        if output == "__OPEN_PETICIONES__":
            self._open_tab("peticiones", "📡 Peticiones")
            self._console_write("📡  Pestaña 'Peticiones' abierta.", "ok")
            return
        if output == "__OPEN_MONITOR__":
            self._open_tab("monitor", "🔍 Monitor")
            self._console_write("🔍  Pestaña 'Monitor' abierta.", "ok")
            self._refresh_connections()
            return
        if output == "__OPEN_AULA__":
            self._open_tab("aula", "🏫 Aula")
            self._console_write("🏫  Pestaña 'Aula' abierta.", "ok")
            return
        if output == "__BLOCK_INSIGHT__":
            self._open_tab("aula", "🏫 Aula")
            self._console_write("🔒 Bloqueando Faronics Insight...", "warn")
            threading.Thread(target=self._console_block_classroom, args=("insight",), daemon=True).start()
            return
        if output == "__UNBLOCK_INSIGHT__":
            self._console_write("🔓 Desbloqueando Faronics Insight...", "warn")
            threading.Thread(target=self._console_unblock_classroom, args=("insight",), daemon=True).start()
            return
        if output == "__BLOCK_REBOOT__":
            self._open_tab("aula", "🏫 Aula")
            self._console_write("🔒 Bloqueando Reboot Restore...", "warn")
            threading.Thread(target=self._console_block_classroom, args=("rebootrestore",), daemon=True).start()
            return
        if output == "__UNBLOCK_REBOOT__":
            self._console_write("🔓 Desbloqueando Reboot Restore...", "warn")
            threading.Thread(target=self._console_unblock_classroom, args=("rebootrestore",), daemon=True).start()
            return
        if output == "__GET_ADMIN__":
            self._do_get_admin()
            return
        if output == "__GET_SUSPICIOUS__":
            self._console_write("🔍  Analizando puertos sospechosos...", "muted")
            threading.Thread(target=self._do_get_suspicious, daemon=True).start()
            return
        if output == "__GET_IP__":
            self._console_write("🌐  Obteniendo información de red...", "muted")
            threading.Thread(target=self._do_get_ip, daemon=True).start()
            return
        if output == "__GET_BAT__":
            self._do_get_bat()
            return
        if isinstance(output, str) and output.startswith("__RUN_BAT__"):
            bat_path = output[len("__RUN_BAT__"):]
            self._do_run_bat(bat_path)
            return
        if output:
            self._console_write(output, level)
        self._status_text.set("Listo")

    def _console_block_classroom(self, app_key: str):
        if not self._admin:
            self.after(0, lambda: self._console_write(
                "❌  Requiere privilegios de Administrador.", "error"))
            return
        results = apply_classroom_block(
            app_key,
            log_callback=lambda m: self.after(0, lambda msg=m: self._console_write(msg, "muted"))
        )
        total = results["ok"] + results["fail"]
        app_name = "Faronics Insight" if app_key == "insight" else "Reboot Restore"
        self.after(0, lambda: (
            self._console_write(f"✅ {app_name}: {results['ok']}/{total} reglas aplicadas.", "ok"),
            self._status_text.set(f"✅ {app_name} bloqueado"),
        ))

    def _console_unblock_classroom(self, app_key: str):
        results = remove_classroom_block(
            app_key,
            log_callback=lambda m: self.after(0, lambda msg=m: self._console_write(msg, "muted"))
        )
        app_name = "Faronics Insight" if app_key == "insight" else "Reboot Restore"
        self.after(0, lambda: self._console_write(
            f"✅ {app_name} desbloqueado. {results['ok']} reglas eliminadas.", "ok"))

    def _do_get_admin(self):
        """Request UAC elevation or report current admin status."""
        if self._admin:
            self._console_write("✅  Ya estás ejecutando FyreWall como Administrador.", "ok")
            return
        self._console_write("🔐  Solicitando privilegios de Administrador...", "warn")
        try:
            script_path = os.path.abspath(sys.argv[0])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script_path}"', None, 1
            )
            self._console_write(
                "✅  Solicitud UAC enviada. Acepta el cuadro de diálogo de Windows.\n"
                "    Se abrirá una nueva ventana de FyreWall con permisos de Admin.",
                "ok"
            )
        except Exception as e:
            self._console_write(f"❌  No se pudo solicitar privilegios: {e}", "error")

    def _do_get_ip(self):
        result = get_ip_info()
        self.after(0, lambda: self._console_write(result, "info"))
        self.after(0, lambda: self._status_text.set("✅  Información de red obtenida"))

    def _do_get_suspicious(self):
        findings = scan_suspicious_ports()
        total = sum(len(v) for v in findings.values())

        def render():
            if total == 0:
                self._console_write(
                    "✅  get-suspicious: No se detectaron puertos sospechosos activos.\n"
                    "    No hay actividad de compartir pantalla, archivos ni diagnósticos.",
                    "ok"
                )
                self._status_text.set("✅  Sin puertos sospechosos")
                return

            self._console_write(
                f"\n🔍  ANÁLISIS DE PUERTOS SOSPECHOSOS — {total} hallazgo(s)", "header"
            )
            self._console_write("─" * 62, "muted")

            for cat_key, cat_label in CATEGORY_NAMES.items():
                hits = findings[cat_key]
                if not hits:
                    continue
                self._console_write(f"\n  {cat_label}", "header")
                for h in hits:
                    state_tag = "ok" if h["state"] == "LISTENING" else "warn"
                    self._console_write(
                        f"  {h['icon']}  Puerto {h['port']}/{h['proto']}  [{h['state']}]",
                        state_tag
                    )
                    self._console_write(f"      ↳ {h['reason']}", "info")
                    self._console_write(
                        f"      ↳ Proceso: {h['process']} (PID {h['pid']})"
                        f"  —  usa 'block-port {h['port']}' para bloquearlo",
                        "muted"
                    )

            self._console_write("\n" + "─" * 62, "muted")
            self._console_write(
                f"  ⚠️   {total} hallazgo(s). Usa 'block-port <puerto>' para bloquear\n"
                "  o 'block-process <proceso>' para cortar el proceso.",
                "warn"
            )
            self._status_text.set(f"⚠️  {total} puerto(s) sospechoso(s) detectado(s)")

        self.after(0, render)

    def _do_get_bat(self):
        """Open file dialog to choose a .bat and run it in the Batch tab."""
        path = filedialog.askopenfilename(
            parent=self,
            title="Selecciona un archivo .bat",
            initialdir=APP_DIR,
            filetypes=[("Archivos Batch", "*.bat"), ("Todos los archivos", "*.*")],
        )
        if not path:
            self._console_write("ℹ️  Selección de .bat cancelada.", "muted")
            return
        self._console_write(f"▶️  Ejecutando: {os.path.basename(path)}", "ok")
        self._do_run_bat(path)

    def _do_run_bat(self, bat_path: str):
        """Open (or reuse) Batch tab and run the .bat there."""
        bat_name = os.path.basename(bat_path)
        # Build/reuse batch tab
        if "batch" not in self._tab_frames:
            frame = tk.Frame(self._content, bg=COLORS["bg"])
            self._tab_frames["batch"] = frame
            self._build_batch_tab(frame)
        self._open_tab("batch", "📜 Batch")
        # Clear and run
        self._batch_out.configure(state="normal")
        self._batch_out.delete("1.0", "end")
        self._batch_out.configure(state="disabled")
        self._batch_title_var.set(f"Ejecutando: {bat_name}")
        self._console_write(f"📜  Pestaña Batch abierta — ejecutando '{bat_name}'", "ok")

        def run():
            try:
                proc = subprocess.Popen(
                    [bat_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    creationflags=CF,
                    cwd=os.path.dirname(bat_path),
                    encoding="cp850",
                    errors="replace",
                )
                for line in proc.stdout:
                    self.after(0, lambda l=line: self._batch_write(l))
                proc.wait()
                code = proc.returncode
                self.after(0, lambda: self._batch_write(
                    f"\n{'─'*40}\n✅  Proceso finalizado (código: {code})\n" if code == 0
                    else f"\n{'─'*40}\n⚠️  Proceso finalizado con error (código: {code})\n"
                ))
                self.after(0, lambda: self._batch_title_var.set(
                    f"{'✅' if code == 0 else '❌'} {bat_name} (finalizado)"
                ))
            except Exception as e:
                self.after(0, lambda: self._batch_write(f"❌  Error ejecutando .bat: {e}\n"))

        threading.Thread(target=run, daemon=True).start()

    def _build_batch_tab(self, frame):
        """Build the Batch execution tab UI."""
        self._batch_title_var = tk.StringVar(value="Batch")

        hdr = tk.Frame(frame, bg=COLORS["surface"], pady=8, padx=12)
        hdr.pack(fill="x")

        tk.Label(hdr, text="📜  BATCH RUNNER",
                 font=FONTS["label"],
                 bg=COLORS["surface"], fg=COLORS["accent"]).pack(side="left")

        self._batch_title_lbl = tk.Label(
            hdr, textvariable=self._batch_title_var,
            font=FONTS["small"],
            bg=COLORS["surface"], fg=COLORS["text_muted"],
        )
        self._batch_title_lbl.pack(side="left", padx=10)

        tk.Button(
            hdr, text="📂 Abrir otro .bat",
            command=self._do_get_bat,
            bg=COLORS["btn"], fg=COLORS["accent"],
            font=FONTS["small"], relief="flat", cursor="hand2",
            padx=8, pady=3, activebackground=COLORS["btn_hover"],
        ).pack(side="right")

        tk.Button(
            hdr, text="🗑 Limpiar",
            command=lambda: (
                self._batch_out.configure(state="normal"),
                self._batch_out.delete("1.0", "end"),
                self._batch_out.configure(state="disabled"),
            ),
            bg=COLORS["btn"], fg=COLORS["text_muted"],
            font=FONTS["small"], relief="flat", cursor="hand2",
            padx=8, pady=3, activebackground=COLORS["btn_hover"],
        ).pack(side="right", padx=(0, 6))

        out_frame = tk.Frame(frame, bg=COLORS["console_bg"])
        out_frame.pack(fill="both", expand=True, padx=12, pady=8)

        self._batch_out = tk.Text(
            out_frame,
            bg=COLORS["console_bg"], fg="#c9d1d9",
            font=("Consolas", 9), relief="flat", bd=0,
            state="disabled", wrap="word", padx=12, pady=10,
        )
        sb = ttk.Scrollbar(out_frame, orient="vertical", command=self._batch_out.yview)
        self._batch_out.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._batch_out.pack(side="left", fill="both", expand=True)

    def _batch_write(self, text: str):
        self._batch_out.configure(state="normal")
        self._batch_out.insert("end", text)
        self._batch_out.configure(state="disabled")
        self._batch_out.see("end")

    def _exec_console(self, cmd: str):
        self._input_var.set(cmd)
        self._on_console_enter(None)
        self._input_entry.focus_set()

    def _console_write(self, text: str, tag: str = "info"):
        self._console_out.configure(state="normal")
        self._console_out.insert("end", text + "\n", tag)
        self._console_out.configure(state="disabled")
        self._console_out.see("end")

    def _clear_console(self):
        self._console_out.configure(state="normal")
        self._console_out.delete("1.0", "end")
        self._console_out.configure(state="disabled")

    def _history_up(self, event):
        if not self._console_history:
            return
        self._history_idx = min(self._history_idx + 1, len(self._console_history) - 1)
        self._input_var.set(self._console_history[self._history_idx])
        self._input_entry.icursor("end")
        return "break"

    def _history_down(self, event):
        if self._history_idx <= 0:
            self._history_idx = -1
            self._input_var.set("")
            return "break"
        self._history_idx -= 1
        self._input_var.set(self._console_history[self._history_idx])
        self._input_entry.icursor("end")
        return "break"

    # ── Visual Autocomplete ───────────────────────────────────────────────

    def _on_key_release(self, event):
        if event.keysym in ("Return", "Escape", "Up", "Down", "Tab"):
            return
        self._show_autocomplete_popup()

    def _show_autocomplete_popup(self):
        current = self._input_var.get()
        if not current:
            self._hide_autocomplete()
            return

        # Special: show bat files when typing "run-bat <partial>"
        if current.lower().startswith("run-bat "):
            prefix = current[len("run-bat "):]
            try:
                bat_files = [
                    f for f in sorted(os.listdir(APP_DIR))
                    if f.lower().endswith(".bat") and f.lower().startswith(prefix.lower())
                ]
            except Exception:
                bat_files = []
            matches = [(f"run-bat {f}", f"ejecutar {f}") for f in bat_files]
        else:
            matches = [(cmd, desc) for cmd, desc in COMMANDS if cmd.startswith(current)]

        if not matches:
            self._hide_autocomplete()
            return

        if self._autocomplete_popup is None or not self._autocomplete_popup.winfo_exists():
            self._autocomplete_popup = tk.Toplevel(self)
            self._autocomplete_popup.wm_overrideredirect(True)
            self._autocomplete_popup.configure(bg=COLORS["border"])

        for w in self._autocomplete_popup.winfo_children():
            w.destroy()

        x = self._input_entry.winfo_rootx()
        y = self._input_entry.winfo_rooty() + self._input_entry.winfo_height() + 2
        self._autocomplete_popup.geometry(f"+{x}+{y}")

        frame = tk.Frame(self._autocomplete_popup, bg=COLORS["surface2"], padx=1, pady=1)
        frame.pack(fill="both", expand=True)

        for i, (cmd, desc) in enumerate(matches[:8]):
            row = tk.Frame(frame, bg=COLORS["surface2"])
            row.pack(fill="x")

            matched_len = len(current)
            cmd_label = tk.Frame(row, bg=COLORS["surface2"])
            cmd_label.pack(side="left", padx=(6, 0), pady=2)

            tk.Label(cmd_label, text=cmd[:matched_len],
                     font=("Consolas", 9, "bold"),
                     bg=COLORS["surface2"], fg=COLORS["accent"]).pack(side="left")
            tk.Label(cmd_label, text=cmd[matched_len:],
                     font=("Consolas", 9),
                     bg=COLORS["surface2"], fg=COLORS["text"]).pack(side="left")

            tk.Label(row, text=f"  {desc}",
                     font=("Segoe UI", 8),
                     bg=COLORS["surface2"], fg=COLORS["text_muted"]).pack(side="left", padx=(4, 8))

            def on_enter(e, r=row):
                r.config(bg=COLORS["accent"])
                for w in r.winfo_children():
                    w.config(bg=COLORS["accent"])
                    for ww in w.winfo_children():
                        ww.config(bg=COLORS["accent"], fg="#000000")

            def on_leave(e, r=row):
                r.config(bg=COLORS["surface2"])
                for w in r.winfo_children():
                    w.config(bg=COLORS["surface2"])
                    for ww in w.winfo_children():
                        ww.config(bg=COLORS["surface2"])

            def on_click(e, c=cmd):
                self._input_var.set(c)
                self._input_entry.icursor("end")
                self._hide_autocomplete()
                self._input_entry.focus_set()

            row.bind("<Enter>", on_enter)
            row.bind("<Leave>", on_leave)
            row.bind("<Button-1>", on_click)
            for w in row.winfo_children():
                w.bind("<Enter>", on_enter)
                w.bind("<Leave>", on_leave)
                w.bind("<Button-1>", on_click)

        self._autocomplete_popup.lift()

    def _hide_autocomplete(self, event=None):
        if self._autocomplete_popup and self._autocomplete_popup.winfo_exists():
            self._autocomplete_popup.destroy()
            self._autocomplete_popup = None

    def _autocomplete_tab(self, event):
        current = self._input_var.get()

        # Special case: autocomplete bat filenames for run-bat
        if current.lower().startswith("run-bat "):
            prefix = current[len("run-bat "):]
            try:
                bat_files = [
                    f for f in os.listdir(APP_DIR)
                    if f.lower().endswith(".bat") and f.lower().startswith(prefix.lower())
                ]
            except Exception:
                bat_files = []
            if len(bat_files) == 1:
                self._input_var.set(f"run-bat {bat_files[0]}")
                self._input_entry.icursor("end")
            elif len(bat_files) > 1:
                common = bat_files[0]
                for m in bat_files[1:]:
                    while not m.lower().startswith(common.lower()):
                        common = common[:-1]
                if len(common) > len(prefix):
                    self._input_var.set(f"run-bat {common}")
                    self._input_entry.icursor("end")
            self._hide_autocomplete()
            return "break"

        matches = [cmd for cmd, _ in COMMANDS if cmd.startswith(current)]
        if len(matches) == 1:
            self._input_var.set(matches[0])
            self._input_entry.icursor("end")
        elif len(matches) > 1:
            common = matches[0]
            for m in matches[1:]:
                while not m.startswith(common):
                    common = common[:-1]
            if len(common) > len(current):
                self._input_var.set(common)
                self._input_entry.icursor("end")
        self._hide_autocomplete()
        return "break"

    # ── Classroom actions ─────────────────────────────────────────────────

    def _classroom_log_write(self, text: str, tag: str = "info"):
        self._classroom_log.configure(state="normal")
        self._classroom_log.insert("end", text + "\n", tag)
        self._classroom_log.configure(state="disabled")
        self._classroom_log.see("end")

    def _clear_classroom_log(self):
        self._classroom_log.configure(state="normal")
        self._classroom_log.delete("1.0", "end")
        self._classroom_log.configure(state="disabled")

    def _classroom_block_all(self, app_key: str):
        app_name = "Faronics Insight" if app_key == "insight" else "Reboot Restore Enterprise"
        if not self._admin:
            messagebox.showwarning(
                "Sin privilegios",
                "Esta operación requiere ejecutar FyreWall como Administrador.",
                parent=self
            )
            return

        self._classroom_log_write(f"\n{'─'*40}", "muted")
        self._classroom_log_write(f"🔒 Bloqueando {app_name}...", "header")

        def run():
            results = apply_classroom_block(
                app_key,
                log_callback=lambda m: self.after(0, lambda msg=m: self._classroom_log_write(msg))
            )
            def done():
                total = results["ok"] + results["fail"]
                skipped = results.get("skipped", 0)
                new_rules = results["ok"] - skipped
                if results["fail"] == 0:
                    self._classroom_log_write(
                        f"\n✅ Completado: {results['ok']}/{total} reglas OK "
                        f"({new_rules} nuevas, {skipped} ya existían).", "ok")
                else:
                    self._classroom_log_write(
                        f"\n⚠️  Completado con errores: {results['ok']} OK / {results['fail']} fallidas.", "warn")
                self._classroom_log_write(
                    "💡 Recuerda crear la tarea de inicio para persistencia tras reinicio.", "warn")
                # Only update status to BLOQUEADO if at least some rules were applied
                if results["ok"] > 0:
                    if app_key == "insight":
                        self._insight_blocked = True
                        self._insight_status_var.set("⬤ BLOQUEADO")
                        self._insight_status_label.config(fg=COLORS["danger"])
                    else:
                        self._rr_blocked = True
                        self._rr_status_var.set("⬤ BLOQUEADO")
                        self._rr_status_label.config(fg=COLORS["danger"])
                    self._status_text.set(f"✅  {app_name} bloqueado")
                else:
                    self._classroom_log_write(
                        f"❌ No se pudo aplicar ninguna regla. ¿Tienes permisos de Administrador?", "error")
                    self._status_text.set(f"❌  Error bloqueando {app_name}")
            self.after(0, done)

        threading.Thread(target=run, daemon=True).start()

    def _classroom_unblock(self, app_key: str):
        app_name = "Faronics Insight" if app_key == "insight" else "Reboot Restore Enterprise"
        if not messagebox.askyesno(
            "Desbloquear",
            f"¿Eliminar las reglas de bloqueo para {app_name}?\n\n"
            "El software de vigilancia podrá volver a funcionar.",
            parent=self
        ):
            return

        self._classroom_log_write(f"\n{'─'*40}", "muted")
        self._classroom_log_write(f"🔓 Desbloqueando {app_name}...", "header")

        def run():
            results = remove_classroom_block(
                app_key,
                log_callback=lambda m: self.after(0, lambda msg=m: self._classroom_log_write(msg))
            )
            def done():
                self._classroom_log_write(f"\n✅ Reglas eliminadas.", "ok")
                if app_key == "insight":
                    self._insight_blocked = False
                    self._insight_status_var.set("⬤ Libre")
                    self._insight_status_label.config(fg=COLORS["success"])
                else:
                    self._rr_blocked = False
                    self._rr_status_var.set("⬤ Libre")
                    self._rr_status_label.config(fg=COLORS["success"])
            self.after(0, done)

        threading.Thread(target=run, daemon=True).start()

    def _classroom_create_task(self, app_key: str):
        app_name = "Faronics Insight" if app_key == "insight" else "Reboot Restore Enterprise"
        self._classroom_log_write(
            f"\n⏰ Creando tarea de inicio persistente para {app_name}...", "header")

        def run():
            ok, msg = create_persistent_startup_task(app_key)
            def done():
                if ok:
                    self._classroom_log_write("  ✅ Tarea de inicio creada correctamente.", "ok")
                    self._classroom_log_write(
                        f"  Nombre: FyreWall_ClassroomBlock_{app_key}\n"
                        f"  Puedes verla en: Inicio > Programador de tareas > FyreWall_*", "muted")
                else:
                    self._classroom_log_write(f"  ❌ Error al crear la tarea:\n  {msg}", "error")
            self.after(0, done)

        threading.Thread(target=run, daemon=True).start()

    def _classroom_disable_services(self, app_key: str):
        app_name = "Faronics Insight" if app_key == "insight" else "Reboot Restore Enterprise"
        self._classroom_log_write(f"\n🛑 Deshabilitando servicios de {app_name}...", "header")

        def run():
            results = disable_classroom_services(app_key)
            def done():
                for r in results:
                    tag = "ok" if "✅" in r else "muted"
                    self._classroom_log_write(r, tag)
                self._classroom_log_write("  Servicios procesados.", "ok")
            self.after(0, done)

        threading.Thread(target=run, daemon=True).start()

    # ── Fake preview ──────────────────────────────────────────────────────

    # ── Window helpers ────────────────────────────────────────────────────

    def _center(self):
        self.update_idletasks()
        w, h = 1180, 780
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = FyreWallApp()
    app.mainloop()
