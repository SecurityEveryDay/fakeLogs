#!/usr/bin/env python3
# gen_ssh_logs.py
# Gera logs SSH "fake" com entradas normais, brute-force de senha/usuário,
# tentativas de chave pública, sudo, etc.
# Uso:
#   python gen_ssh_logs.py --count 100 --interval 0.2 --file out.log
#   python gen_ssh_logs.py --count 100 --interval 0.2 --tcp 192.168.1.10:9997
#   python gen_ssh_logs.py --count 100 --interval 0.2 --udp 192.168.1.10:514

import argparse
import random
import time
import socket
import sys
import signal
from datetime import datetime
from itertools import cycle

def parse_args():
    p = argparse.ArgumentParser(description="Gerador simples de logs fake de SSH (auth.log/secure).")
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
    "203.0.113.5", "198.51.100.23", "8.8.8.8", "172.16.10.100",
    "185.234.219.10", "45.83.123.77"
]

HOSTNAMES = [
    "web01", "db01", "proxy01", "fw01", "srv-lab", "ubuntu-test", "debian-prod"
]

SSH_USERS = [
    "root", "admin", "deployer", "backup", "app", "dev", "ubuntu", "centos", "user"
]

INVALID_USERS = [
    "oracle", "test", "git", "postgres", "mysql", "guest", "demo", "pi"
]

LOCAL_USERS = [
    "root", "deploy", "alice", "bob", "carol", "sysadmin"
]

SUDO_CMDS = [
    "/bin/systemctl restart apache2",
    "/bin/systemctl restart ssh",
    "/usr/bin/apt-get update",
    "/usr/bin/apt-get upgrade -y",
    "/usr/bin/yum update -y",
    "/bin/journalctl -xe",
    "/usr/bin/tail -n 100 /var/log/auth.log"
]

SSH_PORTS = list(range(1024, 65535))

# ---------- Helpers de formatação ----------

def syslog_time(dt=None):
    """Formata timestamp estilo syslog: 'Nov 27 10:15:32'."""
    if dt is None:
        dt = datetime.now()
    # %b = nome curto do mês, %d = dia, %H:%M:%S = hora
    return dt.strftime("%b %d %H:%M:%S")

def format_ssh_log(hostname, process, pid, message, dt=None):
    """
    Formato típico de auth.log / secure:
    Nov 27 10:15:32 hostname sshd[12345]: Mensagem...
    """
    ts = syslog_time(dt)
    return f"{ts} {hostname} {process}[{pid}]: {message}"

# ---------- Geradores de mensagens ----------

def gen_successful_login(rng):
    hostname = rng.choice(HOSTNAMES)
    user = rng.choice(SSH_USERS)
    ip = rng.choice(IPS)
    port = rng.choice(SSH_PORTS)
    pid = rng.randint(1000, 50000)

    msg = (
        f"Accepted password for {user} from {ip} port {port} ssh2"
    )
    return format_ssh_log(hostname, "sshd", pid, msg)

def gen_failed_password(rng, invalid_user=False):
    hostname = rng.choice(HOSTNAMES)
    ip = rng.choice(IPS)
    port = rng.choice(SSH_PORTS)
    pid = rng.randint(1000, 50000)

    if invalid_user:
        user = rng.choice(INVALID_USERS)
        msg = (
            f"Failed password for invalid user {user} from {ip} port {port} ssh2"
        )
    else:
        user = rng.choice(SSH_USERS)
        msg = (
            f"Failed password for {user} from {ip} port {port} ssh2"
        )
    return format_ssh_log(hostname, "sshd", pid, msg)

def gen_pubkey_attempt(rng, success=False):
    hostname = rng.choice(HOSTNAMES)
    ip = rng.choice(IPS)
    port = rng.choice(SSH_PORTS)
    pid = rng.randint(1000, 50000)
    user = rng.choice(SSH_USERS)

    if success:
        msg = (
            f"Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:dummyfingerprint"
        )
    else:
        msg = (
            f"Failed publickey for {user} from {ip} port {port} ssh2: RSA SHA256:dummyfingerprint"
        )
    return format_ssh_log(hostname, "sshd", pid, msg)

def gen_bruteforce_sequence(rng):
    """
    Uma única linha representando um dos passos de brute-force
    (falha de senha ou usuário inválido).
    """
    # 70% invalid user, 30% user conhecido
    if rng.random() < 0.7:
        return gen_failed_password(rng, invalid_user=True)
    else:
        return gen_failed_password(rng, invalid_user=False)

def gen_disconnect_message(rng):
    hostname = rng.choice(HOSTNAMES)
    ip = rng.choice(IPS)
    port = rng.choice(SSH_PORTS)
    pid = rng.randint(1000, 50000)

    msgs = [
        f"Disconnected from authenticating user root {ip} port {port} [preauth]",
        f"Connection closed by authenticating user root {ip} port {port} [preauth]",
        f"Received disconnect from {ip} port {port}:11: disconnected by user",
    ]
    msg = rng.choice(msgs)
    return format_ssh_log(hostname, "sshd", pid, msg)

def gen_bad_protocol(rng):
    hostname = rng.choice(HOSTNAMES)
    ip = rng.choice(IPS)
    port = rng.choice(SSH_PORTS)
    pid = rng.randint(1000, 50000)

    msgs = [
        f"Bad protocol version identification 'GET / HTTP/1.1' from {ip} port {port}",
        f"Invalid user request 'OPTIONS /' from {ip} port {port}",
    ]
    msg = rng.choice(msgs)
    return format_ssh_log(hostname, "sshd", pid, msg)

def gen_sudo_message(rng, success=True):
    hostname = rng.choice(HOSTNAMES)
    user = rng.choice(LOCAL_USERS)
    pid = rng.randint(1000, 50000)
    tty = rng.choice(["pts/0", "pts/1", "pts/2"])
    pwd = rng.choice(["/home/" + user, "/root", "/var/www", "/"])
    cmd = rng.choice(SUDO_CMDS)

    if success:
        msg = (
            f"{user} : TTY={tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}"
        )
    else:
        # Falha de autenticação no sudo
        msg = (
            f"pam_unix(sudo:auth): authentication failure; "
            f"logname={user} uid={rng.randint(1000, 2000)} euid=0 tty={tty} ruser={user} rhost=  user={user}"
        )
    return format_ssh_log(hostname, "sudo", pid, msg)

def gen_system_message(rng):
    hostname = rng.choice(HOSTNAMES)
    pid = rng.randint(1000, 50000)
    msgs = [
        "Server listening on 0.0.0.0 port 22.",
        "Server listening on :: port 22.",
        "Received SIGHUP; restarting.",
        "Reloading configuration.",
    ]
    msg = rng.choice(msgs)
    return format_ssh_log(hostname, "sshd", pid, msg)

# ---------- Seletor principal de linha ----------

def produce_log_entry(rng):
    """
    Escolhe o tipo de log com pesos:
    0.00 - 0.55 => tentativas de login (sucesso/falha "normal")
    0.55 - 0.85 => brute-force (falhas repetidas)
    0.85 - 0.92 => tentativas de chave pública
    0.92 - 0.97 => sudo (sucesso/falha)
    0.97 - 1.00 => mensagens diversas (disconnect / bad protocol / system)
    """
    p = rng.random()

    if p < 0.55:
        # Login normal: mais chance de falha do que de sucesso
        if rng.random() < 0.65:
            return gen_failed_password(rng, invalid_user=False)
        else:
            return gen_successful_login(rng)

    elif p < 0.85:
        # brute-force
        return gen_bruteforce_sequence(rng)

    elif p < 0.92:
        # public key
        return gen_pubkey_attempt(rng, success=(rng.random() < 0.4))

    elif p < 0.97:
        # sudo
        return gen_sudo_message(rng, success=(rng.random() < 0.7))

    else:
        # miscellanea
        q = rng.random()
        if q < 0.4:
            return gen_disconnect_message(rng)
        elif q < 0.7:
            return gen_bad_protocol(rng)
        else:
            return gen_system_message(rng)

# ---------- Helpers de envio ----------

def tcp_send_line(sock, line):
    try:
        if not line.endswith("\n"):
            line = line + "\n"
        sock.sendall(line.encode("utf-8", errors="replace"))
    except Exception as e:
        print(f"[!] Erro ao enviar por TCP: {e}", file=sys.stderr)

def udp_send_line(sock, addr, line):
    try:
        if not line.endswith("\n"):
            line = line + "\n"
        sock.sendto(line.encode("utf-8", errors="replace"), addr)
    except Exception as e:
        print(f"[!] Erro ao enviar por UDP: {e}", file=sys.stderr)

# ---------- Tratamento de sinais ----------

stop_requested = False

def _signal_handler(sig, frame):
    global stop_requested
    stop_requested = True
    print("\n[+] Interrompido pelo utilizador. Finalizando...")

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# ---------- main ----------

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
