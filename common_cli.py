import argparse
import socket
import sys
from dataclasses import dataclass
from typing import Callable, Literal, Optional, Tuple


OutputType = Literal["stdout", "file", "tcp", "udp"]
Writer = Callable[[str], None]


@dataclass
class LogParams:
    count: int          # 0 = infinito
    interval: float     # segundos
    seed: Optional[int]
    output_type: OutputType
    output_target: Optional[str]  # caminho do arquivo ou "ip:porta" para tcp/udp


def add_common_log_args(parser: argparse.ArgumentParser) -> None:
    """
    Adiciona ao parser todos os parâmetros comuns usados nos scripts de log.
    """
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Quantidade de linhas (0 = infinito)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.5,
        help="Intervalo em segundos entre linhas",
    )
    parser.add_argument(
        "--file",
        help="Salvar logs em arquivo (mutuamente exclusivo com --tcp/--udp)",
    )
    parser.add_argument(
        "--tcp",
        help="Enviar logs via TCP, formato ip:porta",
    )
    parser.add_argument(
        "--udp",
        help="Enviar logs via UDP, formato ip:porta",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Seed para geração determinística de logs (opcional)",
    )


def _choose_output(args: argparse.Namespace) -> Tuple[OutputType, Optional[str]]:
    """
    Decide qual saída usar baseado em --file / --tcp / --udp.
    """
    chosen = [
        name
        for name in ("file", "tcp", "udp")
        if getattr(args, name, None)
    ]

    if len(chosen) > 1:
        raise SystemExit(
            f"Use apenas um destino por vez entre --file / --tcp / --udp. Recebido: {chosen}"
        )

    if "file" in chosen:
        return "file", args.file
    if "tcp" in chosen:
        return "tcp", args.tcp
    if "udp" in chosen:
        return "udp", args.udp

    # padrão: stdout
    return "stdout", None


def parse_common_log_params(args: argparse.Namespace) -> LogParams:
    """
    Converte os args em um LogParams padronizado.
    """
    output_type, output_target = _choose_output(args)

    return LogParams(
        count=args.count,
        interval=args.interval,
        seed=getattr(args, "seed", None),
        output_type=output_type,
        output_target=output_target,
    )


def build_writer(params: LogParams) -> Writer:
    """
    Retorna uma função write(line: str) -> None que o script pode usar
    para enviar cada linha de log, independente do destino.
    """

    if params.output_type == "stdout":
        def write_stdout(line: str) -> None:
            print(line, end="" if line.endswith("\n") else "\n")
            sys.stdout.flush()
        # anexamos um atributo para o close_writer saber que não precisa fechar nada
        write_stdout._close = None  # type: ignore[attr-defined]
        return write_stdout

    if params.output_type == "file":
        f = open(params.output_target, "a", encoding="utf-8")

        def write_file(line: str) -> None:
            f.write(line if line.endswith("\n") else line + "\n")
            f.flush()

        write_file._close = f.close  # type: ignore[attr-defined]
        return write_file

    # TCP / UDP
    ip, port_str = params.output_target.split(":", 1)
    port = int(port_str)

    if params.output_type == "tcp":
        sock = socket.create_connection((ip, port))

        def write_tcp(line: str) -> None:
            data = (line if line.endswith("\n") else line + "\n").encode("utf-8")
            sock.sendall(data)

        write_tcp._close = sock.close  # type: ignore[attr-defined]
        return write_tcp

    if params.output_type == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def write_udp(line: str) -> None:
            data = (line if line.endswith("\n") else line + "\n").encode("utf-8")
            sock.sendto(data, (ip, port))

        write_udp._close = sock.close  # type: ignore[attr-defined]
        return write_udp

    raise ValueError(f"Tipo de saída não suportado: {params.output_type}")


def close_writer(writer: Writer) -> None:
    """
    Fecha recursos associados ao writer, se houver.
    """
    close_func = getattr(writer, "_close", None)
    if callable(close_func):
        try:
            close_func()
        except Exception:
            pass
