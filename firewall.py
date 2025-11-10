#!/usr/bin/env python3
"""
gen_firewall_logs.py
Gera logs fake de firewall e:
 - salva em arquivo (--file path)
 - ou envia via TCP para um host/porta (--tcp host:port)

Exemplos:
  python gen_firewall_logs.py --count 100 --interval 0.1 --file logs.txt
  python gen_firewall_logs.py --count 50 --interval 0.2 --tcp 192.168.1.50:9997
  python gen_firewall_logs.py --count 0 --interval 1 --tcp 127.0.0.1:9997
    (count 0 = enviar indefinidamente até Ctrl+C)
"""
import argparse
import random
import socket
import time
from datetime import datetime

SERVICES = ["HTTP", "HTTPS", "SSH", "DNS", "SMTP"]
ACTIONS = ["accept", "close", "deny"]
PROTO_MAP = { "TCP": 6, "UDP": 17, "ICMP": 1 }
LEVELS = ["notice", "warning", "info"]

def rand_ip(private=False):
    if private:
        # choose a private range
        return random.choice([
            f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
            f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
        ])
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rand_port():
    return random.randint(1, 65535)

def gen_log_line():
    now = datetime.utcnow()
    date = now.strftime("%Y-%m-%d")
    time_s = now.strftime("%H:%M:%S")
    logid = f"{random.randint(1,9999999999):010d}"
    typ = "traffic"
    subtype = random.choice(["forward", "local"])
    level = random.choice(LEVELS)
    srcip = rand_ip(private=True)
    srcport = rand_port()
    dstip = rand_ip(private=False)
    dstport = random.choice([80, 443, 22, 53, rand_port()])
    proto = random.choice(list(PROTO_MAP.values()))
    action = random.choice(ACTIONS)
    policyid = random.randint(1, 10)
    service = random.choice(SERVICES)
    duration = random.randint(0, 3600)
    sentbyte = random.randint(0, 200000)
    rcvdbyte = random.randint(0, 200000)
    # simplified single-line key=value style similar to sample
    parts = [
        f"date={date}",
        f"time={time_s}",
        f'logid="{logid}"',
        f"type={typ}",
        f"subtype={subtype}",
        f"level={level}",
        f"srcip={srcip}",
        f"srcport={srcport}",
        f"dstip={dstip}",
        f"dstport={dstport}",
        f"proto={proto}",
        f'action="{action}"',
        f"policyid={policyid}",
        f'service="{service}"',
        f"duration={duration}",
        f"sentbyte={sentbyte}",
        f"rcvdbyte={rcvdbyte}",
    ]
    return " ".join(parts)

def send_tcp(host, port, lines_iterable, reconnect=True):
    """Envia linhas por TCP. Se a conexão cair, tenta reconectar (se reconnect=True)."""
    sock = None
    addr = (host, port)
    try:
        while True:
            try:
                if sock is None:
                    sock = socket.create_connection(addr, timeout=5)
                line = next(lines_iterable)
                sock.sendall((line + "\n").encode("utf-8"))
            except StopIteration:
                break
            except (BrokenPipeError, ConnectionResetError, socket.error) as e:
                # tenta reconectar
                sock = None
                if not reconnect:
                    raise
                time.sleep(1)
                continue
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

def lines_generator(count, interval):
    sent = 0
    while True:
        if count and sent >= count:
            break
        yield gen_log_line()
        sent += 1
        if interval:
            time.sleep(interval)

def append_to_file(path, lines_iterable):
    with open(path, "a", encoding="utf-8") as f:
        for line in lines_iterable:
            f.write(line + "\n")

def parse_args():
    p = argparse.ArgumentParser(description="Gerador simples de logs fake de firewall.")
    p.add_argument("--count", type=int, default=0,
                   help="Quantidade de logs para gerar (0 = indefinido até Ctrl+C).")
    p.add_argument("--interval", type=float, default=0.5,
                   help="Intervalo em segundos entre logs (pode ser decimal).")
    p.add_argument("--file", help="Caminho do arquivo para salvar logs (append).")
    p.add_argument("--tcp", help="Enviar por TCP para host:port (ex: 192.168.1.10:9997).")
    p.add_argument("--seed", type=int, default=None, help="Semente RNG (opcional).")
    return p.parse_args()

def main():
    args = parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    if not args.file and not args.tcp:
        print("ERRO: escolha --file ou --tcp host:port (ou ambos).")
        return

    gen = lines_generator(args.count, args.interval)

    if args.file:
        # Escreve para arquivo (blocking)
        print(f"[+] Salvando logs em {args.file}")
        append_to_file(args.file, gen)
        # if both file and tcp specified, need to regenerate generator; simpler: reopen generator
        if not args.tcp:
            return

    if args.tcp:
        try:
            host_port = args.tcp.split(":")
            host = host_port[0]
            port = int(host_port[1])
        except Exception:
            print("ERRO: formato inválido para --tcp. Use host:port")
            return
        print(f"[+] Enviando logs para {host}:{port} (Ctrl+C para parar)")
        # if file already consumed the generator, create a new one for tcp:
        gen_for_tcp = lines_generator(args.count, args.interval) if args.file else gen
        send_tcp(host, port, gen_for_tcp)
        print("[+] Envio TCP finalizado.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[+] Interrompido pelo usuário.")
