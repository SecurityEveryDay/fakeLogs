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

ACTIONS = ["ALLOW", "DENY", "DROP"]
PROTOCOLS = ["TCP", "UDP", "ICMP"]
PORTS_COMMON = [22, 53, 80, 123, 443, 8080, 3389]


def _random_ip() -> str:
    return str(IPv4Address(random.randint(0, 2**32 - 1)))


def _format_timestamp() -> str:
    # formato tipo firewall/sistema
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_firewall_line() -> str:
    ts = _format_timestamp()
    src_ip = _random_ip()
    dst_ip = _random_ip()
    proto = random.choice(PROTOCOLS)
    src_port = random.randint(1024, 65535)
    dst_port = random.choice(PORTS_COMMON)
    action = random.choice(ACTIONS)
    rule = random.choice(
        ["DEFAULT", "INTERNET_OUT", "VPN_IN", "SSH_BRUTE_FORCE", "WEB_APP"]
    )
    bytes_sent = random.randint(40, 5_000)
    bytes_recv = random.randint(40, 5_000)

    # formato simples tipo key=value
    return (
        f"time={ts} action={action} rule={rule} proto={proto} "
        f"src={src_ip} dst={dst_ip} sport={src_port} dport={dst_port} "
        f"bytes_sent={bytes_sent} bytes_recv={bytes_recv}"
    )


def generate_firewall_logs(params: LogParams) -> None:
    if params.seed is not None:
        random.seed(params.seed)

    writer = build_writer(params)
    try:
        count = 0
        while params.count == 0 or count < params.count:
            line = _build_firewall_line()
            writer(line)
            count += 1
            time.sleep(params.interval)
    finally:
        close_writer(writer)


def main() -> None:
    parser = argparse.ArgumentParser(description="Gerador de logs de firewall falsos")
    add_common_log_args(parser)
    args = parser.parse_args()

    params = parse_common_log_params(args)
    generate_firewall_logs(params)


if __name__ == "__main__":
    main()
