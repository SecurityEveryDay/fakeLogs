#!/usr/bin/env python3
import argparse
import random
import time
from datetime import datetime
from ipaddress import IPv4Address
import urllib.parse

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
    # “normais”
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "curl/8.0.1",
    "python-requests/2.31.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    # suspeitos / scanners
    "sqlmap/1.7.10#stable",
    "Nmap Scripting Engine",
    "Nikto/2.1.6",
    "wpscan v3.8.24",
]

# Perfis por path: probabilidade de ataque e tipos de ataque preferidos
PATH_ATTACK_PROFILES = {
    "/login": {
        "attack_prob": 0.5,
        "preferred": ["sqli"],
    },
    "/wp-login.php": {
        "attack_prob": 0.6,
        "preferred": ["sqli"],
    },
    "/admin": {
        "attack_prob": 0.4,
        "preferred": ["sqli", "other"],
    },
    "/api/v1/auth": {
        "attack_prob": 0.5,
        "preferred": ["sqli"],
    },
    "/api/v1/items": {
        "attack_prob": 0.3,
        "preferred": ["sqli", "xss"],
    },
    "/": {
        "attack_prob": 0.2,
        "preferred": ["xss", "other"],
    },
    "/index.html": {
        "attack_prob": 0.2,
        "preferred": ["xss"],
    },
    "/robots.txt": {
        "attack_prob": 0.05,
        "preferred": ["other"],
    },
}

# Referers legítimos
BENIGN_REFERRERS = [
    "-",
    "https://www.google.com/",
    "https://www.google.com/search?q=example",
    "https://www.bing.com/search?q=login",
    "https://duckduckgo.com/?q=teste",
    "https://example.com/",
    "https://example.com/index.html",
    "https://example.com/blog/seguranca",
    "https://m.example.com/",
]

# Payloads SQL Injection (simples, exemplificativos)
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL,NULL--",
    "admin'--",
    "'; DROP TABLE users;--",
]

# Payloads XSS (simples, exemplificativos)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

# Path traversal / outros padrões suspeitos
OTHER_ATTACK_PATTERNS = [
    "../../etc/passwd",
    "../etc/shadow",
    "..%2f..%2f..%2fwindows/win.ini",
    "/../../../var/log/auth.log",
    "%3Cscript%3Ealert(1)%3C/script%3E",
]

# Query strings benignas
BENIGN_QUERIES = [
    "page=1",
    "page=2&sort=asc",
    "q=teste",
    "q=produto+123",
    "category=books&order=desc",
    "utm_source=newsletter&utm_campaign=promo",
    "username=user&remember_me=1",
    "search=camiseta+azul",
]


def _random_ip() -> str:
    return str(IPv4Address(random.randint(0, 2**32 - 1)))


def _format_timestamp() -> str:
    now = datetime.utcnow()
    return now.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _choose_attack_type_for_path(path: str) -> str:
    """
    Define o tipo de ataque com base no path.
    Se houver tipos preferidos, escolhe um deles com mais chance.
    Caso contrário, usa uma distribuição padrão.
    """
    profile = PATH_ATTACK_PROFILES.get(path)
    if profile and profile.get("preferred"):
        preferred = profile["preferred"]
        # Se houver mais de um preferido, escolhe um aleatoriamente
        return random.choice(preferred)

    # Distribuição padrão (quando não há perfil)
    return random.choices(["sqli", "xss", "other"], weights=[40, 40, 20])[0]


def _build_attack_query(attack_type: str | None = None) -> str:
    """
    Gera uma parte de query string com padrões de ataque
    (SQLi, XSS ou outros). Se attack_type for None,
    escolhe um tipo automaticamente.
    """
    if attack_type is None:
        attack_type = random.choice(["sqli", "xss", "other"])

    if attack_type == "sqli":
        payload = random.choice(SQLI_PAYLOADS)
        # Exemplos mais “login/auth”
        param = random.choice(["username", "user", "id", "login"])
        raw = f"{param}=admin{payload}"
    elif attack_type == "xss":
        payload = random.choice(XSS_PAYLOADS)
        param = random.choice(["q", "search", "s", "query"])
        raw = f"{param}={payload}"
    else:
        payload = random.choice(OTHER_ATTACK_PATTERNS)
        param = random.choice(["file", "path", "page"])
        raw = f"{param}={payload}"

    # Codifica para aparecer como URL “real”
    return urllib.parse.quote_plus(raw, safe="=&")


def _build_request_path() -> str:
    """
    Monta o path da requisição, com chance de ter payload malicioso,
    ajustada por path.
    """
    base_path = random.choice(HTTP_PATHS)
    profile = PATH_ATTACK_PROFILES.get(base_path, None)

    # Probabilidade padrão de ataque caso não haja perfil
    default_attack_prob = 0.2
    attack_prob = profile["attack_prob"] if profile else default_attack_prob

    is_attack = random.random() < attack_prob

    if not is_attack:
        # Requisição benigna, às vezes com query normal
        if random.random() < 0.5:
            query = random.choice(BENIGN_QUERIES)
            return f"{base_path}?{query}"
        return base_path

    # Requisição com payload de ataque, tipo guiado pelo path
    attack_type = _choose_attack_type_for_path(base_path)
    query = _build_attack_query(attack_type)
    return f"{base_path}?{query}"


def _build_referrer() -> str:
    """
    Gera um referrer com mistura de casos:
    - Ausente (“-”)
    - Benigno (Google, site interno, etc.)
    - Malicioso (com payload em query string)
    """
    ref_type = random.choices(
        ["none", "benign", "malicious"],
        weights=[20, 65, 15],
    )[0]

    if ref_type == "none":
        return "-"

    if ref_type == "benign":
        return random.choice(BENIGN_REFERRERS)

    # Referrer malicioso, com tipo de ataque aleatório
    attack_type = random.choice(["sqli", "xss", "other"])
    attack_query = _build_attack_query(attack_type)
    host = random.choice(
        [
            "evil.example.com",
            "attacker.example.net",
            "malicious.test",
        ]
    )
    return f"https://{host}/search.php?{attack_query}"


def _build_apache_line() -> str:
    ip = _random_ip()
    ident = "-"
    user = "-"
    ts = _format_timestamp()
    method = random.choice(HTTP_METHODS)
    path = _build_request_path()
    proto = random.choice(HTTP_PROTOCOLS)
    status = random.choice(HTTP_CODES)
    size = random.randint(100, 5000)
    referrer = _build_referrer()
    ua = random.choice(USER_AGENTS)

    # Formato combined log:
    # %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
    return (
        f'{ip} {ident} {user} [{ts}] "{method} {path} {proto}" '
        f'{status} {size} "{referrer}" "{ua}"'
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
