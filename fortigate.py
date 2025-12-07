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

ACTIONS = ["accept", "deny", "drop"]
PROTOCOLS = ["TCP", "UDP", "ICMP"]
PORTS_COMMON = [22, 53, 80, 123, 443, 8080, 3389]

LEVELS = ["info", "notice", "warning"]
SUBTYPES = ["forward", "local"]

PROTO_NUM = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
}


def _random_ip() -> str:
    return str(IPv4Address(random.randint(0, 2**32 - 1)))


def _current_date_time():
    now = datetime.utcnow()
    return now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S")


def _service_from_port(port: int) -> str:
    if port == 80:
        return "HTTP"
    if port == 443:
        return "HTTPS"
    if port == 22:
        return "SSH"
    if port == 53:
        return "DNS"
    if port == 25 or port == 587 or port == 465:
        return "SMTP"
    if port == 3389:
        return "RDP"
    if port == 8080:
        return "HTTP-ALT"
    return f"tcp/{port}"


def _build_firewall_line() -> str:
    date_str, time_str = _current_date_time()
    src_ip = _random_ip()
    dst_ip = _random_ip()
    proto_name = random.choice(PROTOCOLS)
    proto = PROTO_NUM[proto_name]
    src_port = random.randint(1024, 65535)
    dst_port = random.choice(PORTS_COMMON)
    action = random.choice(ACTIONS)
    level = random.choice(LEVELS)
    subtype = random.choice(SUBTYPES)
    policyid = random.randint(1, 20)
    service = _service_from_port(dst_port)
    duration = random.randint(1, 2000)
    sentbyte = random.randint(40, 200000)
    rcvdbyte = random.randint(40, 200000)
    logid = random.randint(10**8, 10**10 - 1)

    # FortiGate-like format
    return (
        f"date={date_str} time={time_str} "
        f"logid=\"{logid}\" type=traffic subtype={subtype} level={level} "
        f"srcip={src_ip} srcport={src_port} dstip={dst_ip} dstport={dst_port} "
        f"proto={proto} action=\"{action}\" policyid={policyid} "
        f"service=\"{service}\" duration={duration} "
        f"sentbyte={sentbyte} rcvdbyte={rcvdbyte}"
    )


def generate_firewall_logs(params: LogParams) -> None:
    if params.seed is not None:
        random.seed(params.seed)

    writer = build_writer(params)

    # IPs fixos para simular scan de portas (mesmo src/dst)
    scan_src_ip = _random_ip()
    scan_dst_ip = _random_ip()

    def _build_portscan_line() -> str:
        """
        Simula um scan de portas:
        - Mesmo src/dst fixos
        - dstport variando bastante
        - regra implícita de scan em policyid específico
        """
        date_str, time_str = _current_date_time()
        proto = PROTO_NUM["TCP"]
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 65535)
        action = random.choice(["deny", "drop"])
        level = random.choice(LEVELS)
        subtype = "forward"
        policyid = 99  # policy de "scan"
        service = _service_from_port(dst_port)
        duration = random.randint(1, 10)
        sentbyte = random.randint(0, 500)
        rcvdbyte = random.randint(0, 500)
        logid = random.randint(10**8, 10**10 - 1)

        return (
            f"date={date_str} time={time_str} "
            f"logid=\"{logid}\" type=traffic subtype={subtype} level={level} "
            f"srcip={scan_src_ip} srcport={src_port} dstip={scan_dst_ip} dstport={dst_port} "
            f"proto={proto} action=\"{action}\" policyid={policyid} "
            f"service=\"{service}\" duration={duration} "
            f"sentbyte={sentbyte} rcvdbyte={rcvdbyte}"
        )

    try:
        count = 0
        while params.count == 0 or count < params.count:
            # ~70% normal, ~30% logs de scan de portas
            r = random.random()
            if r < 0.3:
                line = _build_portscan_line()
            else:
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
