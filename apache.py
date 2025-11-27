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

HTTP_METHODS = ["GET", "POST", "HEAD", "PUT", "DELETE"]
HTTP_PATHS = [
    "/",
    "/index.html",
    "/login",
    "/admin",
    "/wp-login.php",
    "/api/v1/items",
    "/api/v1/auth",
    "/robots.txt",
]
HTTP_PROTOCOLS = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0"]
HTTP_CODES = [200, 200, 200, 301, 302, 400, 401, 403, 404, 500, 502]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "curl/8.0.1",
    "python-requests/2.31.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
]


def _random_ip() -> str:
    return str(IPv4Address(random.randint(0, 2**32 - 1)))


def _format_timestamp() -> str:
    now = datetime.utcnow()
    return now.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _build_apache_line() -> str:
    ip = _random_ip()
    ident = "-"
    user = "-"
    ts = _format_timestamp()
    method = random.choice(HTTP_METHODS)
    path = random.choice(HTTP_PATHS)
    proto = random.choice(HTTP_PROTOCOLS)
    status = random.choice(HTTP_CODES)
    size = random.randint(100, 5000)
    referrer = "-"
    ua = random.choice(USER_AGENTS)

    return (
        f'{ip} {ident} {user} [{ts}] "{method} {path} {proto}" '
        f"{status} {size} \"{referrer}\" \"{ua}\""
    )


def generate_apache_logs(params: LogParams) -> None:
    if params.seed is not None:
        random.seed(params.seed)

    writer = build_writer(params)
    try:
        count = 0
        while params.count == 0 or count < params.count:
            line = _build_apache_line()
            writer(line)
            count += 1
            time.sleep(params.interval)
    finally:
        close_writer(writer)


def main() -> None:
    parser = argparse.ArgumentParser(description="Gerador de logs Apache falsos")
    add_common_log_args(parser)
    args = parser.parse_args()

    params = parse_common_log_params(args)
    generate_apache_logs(params)


if __name__ == "__main__":
    main()
