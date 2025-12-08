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

USERS = [
    "bulma", "goku.ssj", "vegeta", "trunks.future", "gohan",
    "krillin", "tien", "yamcha", "piccolo.sr", "frieza",
    "zarbon", "dr.brief", "ginyu", "jeice", "recoome", "burter", "devops"
]

HOSTS = [
    "capsulecorp", "training", "security", "database", "capsulecloud"
]

SSH_RESULTS = ["Accepted", "Failed", "Invalid"]
SSH_AUTH_METHODS = ["password", "publickey"]
SSH_PORTS = [22, 2222]


def _random_ip() -> str:
    return str(IPv4Address(random.randint(0, 2**32 - 1)))


def _format_timestamp() -> str:
    return datetime.utcnow().strftime("%b %d %H:%M:%S")


def _build_ssh_line() -> str:
    ts = _format_timestamp()
    host = random.choice(HOSTS)
    proc = "sshd"
    pid = random.randint(1000, 9999)
    user = random.choice(USERS)
    src_ip = _random_ip()
    port = random.choice(SSH_PORTS)
    result = random.choice(SSH_RESULTS)
    auth_method = random.choice(SSH_AUTH_METHODS)

    if result == "Accepted":
        msg = (
            f"{ts} {host} {proc}[{pid}]: {result} {auth_method} for {user} "
            f"from {src_ip} port {port} ssh2"
        )
    elif result == "Failed":
        msg = (
            f"{ts} {host} {proc}[{pid}]: {result} password for {user} "
            f"from {src_ip} port {port} ssh2"
        )
    else:  # Invalid
        msg = (
            f"{ts} {host} {proc}[{pid}]: {result} user {user} "
            f"from {src_ip} port {port}"
        )

    return msg


def generate_ssh_logs(params: LogParams) -> None:
    if params.seed is not None:
        random.seed(params.seed)

    writer = build_writer(params)

    spray_ip = _random_ip()
    brute_ip = _random_ip()
    brute_user = random.choice(USERS)

    def _build_password_spray_line() -> str:
        ts = _format_timestamp()
        host = random.choice(HOSTS)
        proc = "sshd"
        pid = random.randint(1000, 9999)
        user = random.choice(USERS)
        port = random.choice(SSH_PORTS)
        return (
            f"{ts} {host} {proc}[{pid}]: Failed password for {user} "
            f"from {spray_ip} port {port} ssh2"
        )

    def _build_bruteforce_line() -> str:
        ts = _format_timestamp()
        host = random.choice(HOSTS)
        proc = "sshd"
        pid = random.randint(1000, 9999)
        port = random.choice(SSH_PORTS)
        return (
            f"{ts} {host} {proc}[{pid}]: Failed password for {brute_user} "
            f"from {brute_ip} port {port} ssh2"
        )

    try:
        count = 0
        while params.count == 0 or count < params.count:
            r = random.random()
            if r < 0.2:
                line = _build_password_spray_line()
            elif r < 0.4:
                line = _build_bruteforce_line()
            else:
                line = _build_ssh_line()

            writer(line)
            count += 1
            time.sleep(params.interval)
    finally:
        close_writer(writer)


def main() -> None:
    parser = argparse.ArgumentParser(description="Gerador de logs SSH falsos")
    add_common_log_args(parser)
    args = parser.parse_args()

    params = parse_common_log_params(args)
    generate_ssh_logs(params)


if __name__ == "__main__":
    main()
