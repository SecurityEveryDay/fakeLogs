#!/usr/bin/env python3
# gen_apache_logs.py
# Gera logs Apache "fake" com entradas normais e tentativas de XSS, SQLi, brute-force em arquivos/dirs e brute-force de usuários.
# Uso:
#   python gen_apache_logs.py --count 100 --interval 0.2 --file out.log
#   python gen_apache_logs.py --count 100 --interval 0.2 --tcp 192.168.1.10:9997
#   python gen_apache_logs.py --count 100 --interval 0.2 --udp 192.168.1.10:514

import argparse
import random
import time
import socket
import sys
import signal
from datetime import datetime, timezone
from itertools import cycle

def parse_args():
    p = argparse.ArgumentParser(description="Gerador simples de logs fake de Apache.")
    p.add_argument("--count", type=int, default=0,
                   help="Quantidade de logs para gerar (0 = indefinido até Ctrl+C).")
    p.add_argument("--interval", type=float, default=0.5,
                   help="Intervalo em segundos entre logs (pode ser decimal).")
    p.add_argument("--file", help="Caminho do arquivo para salvar logs (append).")
    p.add_argument("--tcp", help="Enviar por TCP para host:port (ex: 192.168.1.10:9997).")
    p.add_argument("--udp", help="Enviar por UDP para host:port (ex: 192.168.1.10:514).")
    p.add_argument("--seed", type=int, default=None, help="Semente RNG (opcional).")
    return p.parse_args()

# ---------- Dados de exemplo ----------
IPS = [
    "192.168.1.10", "10.0.0.5", "172.16.0.3",
    "203.0.113.5", "198.51.100.23", "8.8.8.8", "172.16.10.100"
]

METHODS = ["GET", "POST", "HEAD", "PUT"]
STATUS_CODES = [200, 301, 302, 400, 401, 403, 404, 500]
RESOURCES = [
    "/", "/index.html", "/home", "/about", "/contact",
    "/search", "/api/data", "/products", "/download"
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Wget/1.20.3 (linux-gnu)"
]

# payloads maliciosos simulados
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "%3Cscript%3Ealert(1)%3C/script%3E"
]
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' OR 1=1 -- ",
    "\" OR \"\" = \""
]

BRUTE_FILE_PATHS = [
    "/admin/", "/admin.php", "/wp-login.php", "/backup.zip",
    "/.git/config", "/config.php.bak", "/phpmyadmin/", "/server-status"
]

BRUTE_USERNAMES = ["root", "admin", "test", "demo", "user", "support", "administrator"]
BRUTE_PASSWORDS = ["1234", "password", "admin", "letmein", "qwerty", "P@ssw0rd"]

REFERERS = [
    "-", "https://google.com/search?q=test", "https://hacker.local/",
    "https://bing.com/search?q=admin"
]

# small helper to format Apache combined log
def apache_time(dt=None):
    if dt is None:
        dt = datetime.now(timezone.utc)
    # Example: 10/Oct/2000:13:55:36 -0700
    return dt.strftime("%d/%b/%Y:%H:%M:%S %z")

def format_log(ip, ident, user, dt, request, status, size, referer, ua):
    return f'{ip} {ident} {user} [{apache_time(dt)}] "{request}" {status} {size} "{referer}" "{ua}"'

# Generators for patterns
def gen_normal_request():
    method = random.choice(METHODS)
    res = random.choice(RESOURCES)
    if method in ("POST", "PUT"):
        # simulated payload length
        body = f"action=submit&value={random.randint(1,9999)}"
        req = f'{method} {res} HTTP/1.1'
    else:
        q = ""
        # small chance to include a query param
        if random.random() < 0.3:
            q = f'?q={random.choice(["test","hello","world","php"]) }'
        req = f'{method} {res}{q} HTTP/1.1'
    return req

def gen_xss_request():
    method = "GET"
    path = random.choice(RESOURCES) + "?q=" + random.choice(XSS_PAYLOADS)
    return f'{method} {path} HTTP/1.1'

def gen_sqli_request():
    method = random.choice(["GET", "POST"])
    if method == "GET":
        path = random.choice(RESOURCES) + "?id=" + random.choice(SQLI_PAYLOADS)
        return f'{method} {path} HTTP/1.1'
    else:
        path = "/login"
        return f'{method} {path} HTTP/1.1'

def gen_bruteforce_files_request():
    method = "GET"
    path = random.choice(BRUTE_FILE_PATHS)
    # add random noisy params sometimes
    if random.random() < 0.4:
        path += f"?v={random.randint(1,999)}"
    return f'{method} {path} HTTP/1.1'

def gen_bruteforce_user_request(fail=True):
    # simulate login attempts to /login or /wp-login.php
    method = "POST"
    endpoint = random.choice(["/login", "/wp-login.php", "/admin/login"])
    user = random.choice(BRUTE_USERNAMES)
    pwd = random.choice(BRUTE_PASSWORDS)
    # we put credentials in query for the log request line to make it visible
    query = f"?user={user}&pass={pwd}"
    req = f'{method} {endpoint}{query} HTTP/1.1'
    return req, user, pwd

# wrapper to produce a single log entry type chosen by probability
def produce_log_entry(rng):
    p = rng.random()
    ip = rng.choice(IPS)
    ident = "-"  # RFC 1413 identity (raramente usado)
    user = "-"   # usuário autenticado, se houver
    dt = datetime.now(timezone.utc)
    ua = rng.choice(USER_AGENTS)
    referer = rng.choice(REFERERS)
    size = rng.randint(80, 4000)

    # Weighted selection of log types
    # 0.0 - 0.70 => normal
    # 0.70 - 0.80 => XSS
    # 0.80 - 0.88 => SQLi
    # 0.88 - 0.96 => brute files/dirs
    # 0.96 - 1.00 => brute users
    if p < 0.70:
        req = gen_normal_request()
        status = rng.choice([200, 200, 301, 404, 500])  # mais chance de 200
    elif p < 0.80:
        req = gen_xss_request()
        status = rng.choice([200, 400, 403, 404])
        # às vezes o referer indica origem do ataque
        referer = "https://attacker.example/"
    elif p < 0.88:
        req = gen_sqli_request()
        status = rng.choice([200, 400, 500, 404])
        referer = "-"
    elif p < 0.96:
        req = gen_bruteforce_files_request()
        status = rng.choice([403, 404, 200])
        referer = "-"
    else:
        req, u, pwd = gen_bruteforce_user_request()
        status = rng.choices([401, 401, 401, 302, 200], weights=[60,20,10,5,5])[0]
        user = u if status in (200, 302) else "-"
        size = rng.randint(200, 1200)

    return format_log(ip, ident, user, dt, req, status, size, referer, ua)

# TCP send helper
def tcp_send_line(sock, line):
    try:
        if not line.endswith("\n"):
            line = line + "\n"
        sock.sendall(line.encode("utf-8", errors="replace"))
    except Exception as e:
        print(f"[!] Erro ao enviar por TCP: {e}", file=sys.stderr)

# UDP send helper
def udp_send_line(sock, addr, line):
    try:
        if not line.endswith("\n"):
            line = line + "\n"
        sock.sendto(line.encode("utf-8", errors="replace"), addr)
    except Exception as e:
        print(f"[!] Erro ao enviar por UDP: {e}", file=sys.stderr)

# Graceful Ctrl+C
stop_requested = False
def _signal_handler(sig, frame):
    global stop_requested
    stop_requested = True
    print("\n[+] Interrompido pelo utilizador. Finalizando...")

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

def main():
    args = parse_args()

    rng = random.Random(args.seed)

    tcp_sock = None
    if args.tcp:
        try:
            host, port_str = args.tcp.split(":")
            port = int(port_str)
            tcp_sock = socket.create_connection((host, port), timeout=5)
            print(f"[+] Conectado a {host}:{port} (TCP).")
        except Exception as e:
            print(f"[!] Não foi possível conectar a {args.tcp}: {e}", file=sys.stderr)
            tcp_sock = None

    udp_sock = None
    udp_addr = None
    if args.udp:
        try:
            host, port_str = args.udp.split(":")
            port = int(port_str)
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_addr = (host, port)
            print(f"[+] Enviando para {host}:{port} (UDP).")
        except Exception as e:
            print(f"[!] Não foi possível configurar UDP para {args.udp}: {e}", file=sys.stderr)
            udp_sock = None
            udp_addr = None

    outfile = None
    if args.file:
        try:
            outfile = open(args.file, "a", encoding="utf-8")
            print(f"[+] Gravando logs em: {args.file}")
        except Exception as e:
            print(f"[!] Erro ao abrir arquivo {args.file} para append: {e}", file=sys.stderr)
            outfile = None

    generated = 0
    target = args.count if args.count > 0 else None  # 0 => infinito

    try:
        while True:
            if stop_requested:
                break
            if target is not None and generated >= target:
                break

            line = produce_log_entry(rng)
            out_line = f"{line}"

            # STDOUT
            print(out_line)

            # Arquivo
            if outfile:
                try:
                    outfile.write(out_line + "\n")
                    outfile.flush()
                except Exception as e:
                    print(f"[!] Erro ao escrever no arquivo: {e}", file=sys.stderr)

            # TCP
            if tcp_sock:
                tcp_send_line(tcp_sock, out_line)

            # UDP
            if udp_sock and udp_addr:
                udp_send_line(udp_sock, udp_addr, out_line)

            generated += 1
            time.sleep(args.interval)
    finally:
        if outfile:
            outfile.close()
        if tcp_sock:
            try:
                tcp_sock.close()
            except:
                pass
        if udp_sock:
            try:
                udp_sock.close()
            except:
                pass
        print(f"[+] Finalizado. Logs gerados: {generated}")

if __name__ == "__main__":
    main()
