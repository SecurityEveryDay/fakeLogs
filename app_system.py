#!/usr/bin/env python3
import argparse
import random
import time
from datetime import datetime
from ipaddress import IPv4Address

from common_cli import (
    LogParams,
    add_common_log_args,
    parse_common_log_params,
    build_writer,
    close_writer,
)

APP_USERS = [
    "bulma",
    "goku.ssj",
    "vegeta",
    "trunks.future",
    "gohan",
    "krillin",
    "tien",
    "yamcha",
    "piccolo.sr",
    "frieza",
    "zarbon",
    "dr.brief",
    "ginyu",
    "jeice",
    "recoome",
    "burter",
]

SYSTEMS = [
    "capsulecorp.local",
    "training.room",
    "security.core",
    "database.engine",
    "capsulecloud.api",
]

LOG_LEVEL_INFO = "INFO"
LOG_LEVEL_WARN = "WARN"

RESOURCE_FILES = [
    "energy_matrix_v4.json",
    "session_cache.tmp",
    "maintenance_specs.md",
    "reaction_test_data.csv",
    "firewall_rules.yaml",
    "mission_report_beta.pdf",
]

TRAINING_MODULES = [
    "focus_control_advanced",
    "gravity_150g",
    "ki_control_basic",
    "defense_pattern_v3",
]

TABLE_NAMES = [
    "capsule_inventory",
    "experiment_logs",
    "training_sessions",
]

CONTAINERS = [
    "env_x11_prod",
    "env_x10_prod",
    "env_test_09",
    "env_test_07",
]


def _random_ip() -> str:
    return str(IPv4Address(random.randint(0, 2**32 - 1)))


def _format_timestamp() -> str:
    # Exemplo: "2025-03-13 08:12:45"
    return datetime.utcnow().strftime("%Y:%m:%d %H:%M:%S")


def _build_capsulecorp_line(ts: str) -> str:
    user = random.choice(APP_USERS)
    level = LOG_LEVEL_INFO
    system = "capsulecorp.local"
    action = random.choice(["create_resource", "update_profile", "delete_file", "read_document"])
    src_ip = _random_ip()

    if action == "create_resource":
        resource = random.choice(RESOURCE_FILES)
        size = random.choice(["4KB", "10KB", "2MB", "10MB"])
        return (
            f'{ts} {level}  [{system}] User {user} created resource "{resource}" '
            f'from workstation {src_ip} (size: {size})'
        )
    elif action == "update_profile":
        field = random.choice(["access_level", "email", "mfa_enabled"])
        return (
            f'{ts} {level}  [{system}] User {user} updated profile attribute "{field}" via web portal'
        )
    elif action == "delete_file":
        resource = random.choice(RESOURCE_FILES)
        return (
            f'{ts} {level}  [{system}] User {user} deleted file "{resource}" from host {src_ip}'
        )
    else:  # read_document
        resource = random.choice(RESOURCE_FILES)
        return (
            f'{ts} {level}  [{system}] User {user} read document "{resource}" from remote session'
        )


def _build_training_room_line(ts: str) -> str:
    user = random.choice(APP_USERS)
    level = LOG_LEVEL_INFO
    system = "training.room"
    action = random.choice(["access_module", "upload_file", "update_schedule", "delete_record"])
    src_ip = _random_ip()

    if action == "access_module":
        module = random.choice(TRAINING_MODULES)
        console = random.choice(["TR-01", "TR-02", "TR-07", "TR-09"])
        return (
            f'{ts} {level}  [{system}] User {user} accessed training module "{module}" '
            f'via console station {console}'
        )
    elif action == "upload_file":
        filename = random.choice(["reaction_test_data.csv", "battle_report_01.txt", "focus_stats.json"])
        size = random.choice(["1MB", "2MB", "3MB", "12MB"])
        return (
            f'{ts} {level}  [{system}] User {user} uploaded file "{filename}" '
            f'(size: {size}) from IP {src_ip}'
        )
    elif action == "update_schedule":
        session = random.choice(["morning", "afternoon", "evening"])
        return (
            f'{ts} {level}  [{system}] User {user} updated training schedule '
            f'(session={session}) on system TR-SCHEDULE'
        )
    else:  # delete_record
        rec_id = random.randint(100, 999)
        return (
            f'{ts} {level}  [{system}] User {user} deleted record "session_log_{rec_id}" '
            f'from DB interface'
        )


def _build_security_core_line(ts: str) -> str:
    user = random.choice(APP_USERS + ["nappa"])
    system = "security.core"
    action = random.choice(["failed_login", "grant_permission", "read_resource", "update_mfa"])

    if action == "failed_login":
        level = LOG_LEVEL_WARN
        src_ip = _random_ip()
        reason = random.choice(["invalid password", "user not found", "MFA required"])
        return (
            f'{ts} {level}  [{system}] Failed login attempt for user {user} '
            f'from IP {src_ip} ({reason})'
        )

    level = LOG_LEVEL_INFO

    if action == "grant_permission":
        permission = random.choice(["audit.viewer", "system.monitoring", "incident.responder"])
        return (
            f'{ts} {level}  [{system}] User {user} granted permission "{permission}" '
            f'through admin console'
        )
    elif action == "read_resource":
        resource = random.choice(["firewall_rules.yaml", "access_policies.yml", "vpn_config.conf"])
        return (
            f'{ts} {level}  [{system}] User {user} read resource "{resource}" '
            f'from security dashboard'
        )
    else:  # update_mfa
        method = random.choice(["token", "sms", "app"])
        return (
            f'{ts} {level}  [{system}] User {user} updated MFA configuration '
            f'(method={method}) via REST API'
        )


def _build_database_engine_line(ts: str) -> str:
    user = random.choice(APP_USERS + ["dr.brief"])
    level = LOG_LEVEL_INFO
    system = "database.engine"
    action = random.choice(["create_table", "update_record", "read_record", "delete_record"])
    table = random.choice(TABLE_NAMES)

    if action == "create_table":
        return (
            f'{ts} {level}  [{system}] User {user} created table "{table}" from SQL client'
        )
    elif action == "update_record":
        rec_id = random.randint(100, 999)
        return (
            f'{ts} {level}  [{system}] User {user} updated record id={rec_id} in "{table}" '
            f'using endpoint /db/update'
        )
    elif action == "read_record":
        rec_id = random.randint(100, 999)
        return (
            f'{ts} {level}  [{system}] User {user} read entry id={rec_id} from "{table}" '
            f'via monitoring service'
        )
    else:  # delete_record
        rec_id = random.randint(100, 999)
        return (
            f'{ts} {level}  [{system}] User {user} deleted entry id={rec_id} from "{table}" '
            f'using admin GUI'
        )


def _build_capsulecloud_api_line(ts: str) -> str:
    user = random.choice(APP_USERS + ["ginyu", "jeice", "recoome", "burter"])
    level = LOG_LEVEL_INFO
    system = "capsulecloud.api"
    action = random.choice(["upload_file", "create_container", "update_container", "delete_container"])

    if action == "upload_file":
        filename = random.choice(["mission_report_beta.pdf", "mission_report_alpha.pdf", "deploy_log.txt"])
        size = random.choice(["5MB", "8MB", "10MB", "12MB"])
        client_ver = random.choice(["v2.3", "v2.4", "v3.0"])
        return (
            f'{ts} {level}  [{system}] User {user} uploaded file "{filename}" '
            f'(size: {size}) from API client {client_ver}'
        )
    elif action == "create_container":
        container = random.choice(CONTAINERS)
        node = random.choice(["CC-NODE-01", "CC-NODE-02", "CC-NODE-03"])
        return (
            f'{ts} {level}  [{system}] User {user} created container "{container}" from node {node}'
        )
    elif action == "update_container":
        container = random.choice(CONTAINERS)
        status = random.choice(["running", "paused", "restarting"])
        return (
            f'{ts} {level}  [{system}] User {user} updated container "{container}" '
            f'(status={status}) via API token'
        )
    else:  # delete_container
        container = random.choice(CONTAINERS)
        return (
            f'{ts} {level}  [{system}] User {user} deleted container "{container}" '
            f'from orchestrator panel'
        )


def _build_app_line() -> str:
    ts = _format_timestamp()
    system = random.choice(SYSTEMS)

    if system == "capsulecorp.local":
        return _build_capsulecorp_line(ts)
    elif system == "training.room":
        return _build_training_room_line(ts)
    elif system == "security.core":
        return _build_security_core_line(ts)
    elif system == "database.engine":
        return _build_database_engine_line(ts)
    else:  # "capsulecloud.api"
        return _build_capsulecloud_api_line(ts)


def generate_app_logs(params: LogParams) -> None:
    if params.seed is not None:
        random.seed(params.seed)

    writer = build_writer(params)
    try:
        count = 0
        while params.count == 0 or count < params.count:
            line = _build_app_line()
            writer(line)
            count += 1
            time.sleep(params.interval)
    finally:
        close_writer(writer)


def main() -> None:
    parser = argparse.ArgumentParser(description="Gerador de logs de aplicação falsos (Capsule Corp)")
    add_common_log_args(parser)
    args = parser.parse_args()

    params = parse_common_log_params(args)
    generate_app_logs(params)


if __name__ == "__main__":
    main()
