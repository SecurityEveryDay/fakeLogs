#!/usr/bin/env python3
"""
Orquestrador para os geradores de logs fake.

Exemplos:

    python fakeLogs.py --apache udp:192.168.0.10:514 --fortigate file:fw.log --ssh stdout --count 0 --interval 1

Destinos aceitos:
    stdout
    file:/caminho/para/arquivo.log
    tcp:IP:PORTA
    udp:IP:PORTA
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from typing import Dict, List, Tuple, Optional

BASE_SCRIPTS = {
    "apache": "apache.py",
    "fortigate": "fortigate.py",
    "ssh": "ssh.py",
}

def parse_destination(dest: str) -> Tuple[str, Optional[str]]:
    """
    Retorna (tipo, valor).

    tipo pode ser: stdout, file, tcp, udp
    valor:
      - stdout -> None
      - file -> caminho do arquivo
      - tcp/udp -> "IP:PORTA"
    """
    if dest == "stdout":
        return "stdout", None

    if ":" not in dest:
        raise ValueError(f"Destino inválido: {dest}")

    kind, rest = dest.split(":", 1)
    kind = kind.lower()

    if kind == "file":
        if not rest:
            raise ValueError("Destino file: precisa de caminho, ex: file:apache.log")
        return "file", rest

    if kind in ("tcp", "udp"):
        if ":" not in rest:
            raise ValueError(f"Destino {kind}: precisa IP:PORTA, ex: {kind}:192.168.0.10:514")
        return kind, rest

    raise ValueError(f"Tipo de destino desconhecido: {kind}")

def build_command(
    script: str,
    count: int,
    interval: float,
    seed: Optional[int],
    dest_kind: str,
    dest_value: Optional[str],
) -> List[str]:
    cmd = [sys.executable, script, "--count", str(count), "--interval", str(interval)]
    if seed is not None:
        cmd.extend(["--seed", str(seed)])

    if dest_kind == "stdout":
        # não passamos nada -> script imprime na tela
        pass
    elif dest_kind == "file":
        cmd.extend(["--file", dest_value])
    elif dest_kind in ("tcp", "udp"):
        cmd.extend([f"--{dest_kind}", dest_value])
    else:
        raise ValueError(f"Destino não suportado: {dest_kind}")

    return cmd

def main() -> None:
    parser = argparse.ArgumentParser(description="Orquestrador para múltiplos geradores de fake logs.")
    parser.add_argument("--apache", help="Destino para logs Apache (stdout | file:CAMINHO | tcp:IP:PORTA | udp:IP:PORTA)")
    parser.add_argument("--fortigate", help="Destino para logs de firewall (stdout | file:CAMINHO | tcp:IP:PORTA | udp:IP:PORTA)")
    parser.add_argument("--ssh", help="Destino para logs de SSH (stdout | file:CAMINHO | tcp:IP:PORTA | udp:IP:PORTA)")
    parser.add_argument("--count", type=int, default=0, help="Quantidade de linhas por script (0 = infinito, segue comportamento atual).")
    parser.add_argument("--interval", type=float, default=0.5, help="Intervalo em segundos entre linhas.")
    parser.add_argument("--seed", type=int, default=None, help="Seed global de RNG (cada script recebe o mesmo valor, opcional).")

    args = parser.parse_args()

    # mapeia qual tipo foi pedido e seu destino
    requested: Dict[str, str] = {}
    if args.apache:
        requested["apache"] = args.apache
    if args.fortigate:
        requested["fortigate"] = args.fortigate
    if args.ssh:
        requested["ssh"] = args.ssh

    if not requested:
        parser.error("Você precisa passar pelo menos um dos flags: --apache, --fortigate ou --ssh.")

    processes: List[subprocess.Popen] = []

    # cria um processinho para cada tipo escolhido
    for kind, dest in requested.items():
        script_name = BASE_SCRIPTS[kind]
        script_path = os.path.join(os.path.dirname(__file__), script_name)

        if not os.path.exists(script_path):
            print(f"[!] Script não encontrado: {script_path}", file=sys.stderr)
            continue

        try:
            dest_kind, dest_value = parse_destination(dest)
            cmd = build_command(script_path, args.count, args.interval, args.seed, dest_kind, dest_value)
        except ValueError as e:
            print(f"[!] Erro nos parâmetros de {kind}: {e}", file=sys.stderr)
            continue

        print(f"[+] Iniciando {kind} -> {dest} ({' '.join(cmd)})")
        p = subprocess.Popen(cmd)
        processes.append(p)

    if not processes:
        print("[!] Nenhum processo foi iniciado (verifique erros acima).", file=sys.stderr)
        sys.exit(1)

    # Ctrl+C para matar todo mundo
    def handle_sigint(signum, frame):
        print("\n[+] Encerrando todos os geradores...")
        for p in processes:
            if p.poll() is None:  # ainda rodando
                try:
                    p.terminate()
                except Exception:
                    pass
        # dá um tempo curto para terminar, depois mata na força se precisar
        time.sleep(1)
        for p in processes:
            if p.poll() is None:
                try:
                    p.kill()
                except Exception:
                    pass
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    # fica vivo enquanto tiver processo rodando
    try:
        while True:
            still_running = any(p.poll() is None for p in processes)
            if not still_running:
                break
            time.sleep(0.5)
    finally:
        # limpeza de segurança
        for p in processes:
            if p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass

if __name__ == "__main__":
    main()
