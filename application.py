from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
import random
import string

app = Flask(__name__)

LOGS = []


# ----- GERADORES FAKES DRAGON BALL Z ----- #

def random_warrior():
    warriors = [
        "goku", "vegeta", "gohan", "piccolo", "trunks", "goten",
        "krillin", "bulma", "freeza", "cell", "majin_buu",
        "beerus", "whis", "jin", "broly", "pan", "vados"
    ]
    suffix = str(random.randint(1, 999))
    return f"{random.choice(warriors)}_{suffix}"


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def random_resource():
    resources = [
        "/api/v1/warriors",
        "/api/v1/warriors/earth",
        "/api/v1/warriors/vegeta",
        "/api/v1/planets",
        "/api/v1/planets/earth",
        "/api/v1/planets/namek",
        "/api/v1/dragonballs",
        "/api/v1/dragonballs/radar",
        "/api/v1/ki/auth",
        "/api/v1/ki/training",
        "/api/v1/tournament",
    ]
    return random.choice(resources)


def random_power_level():
    # só pra ficar engraçado: 1 a 1.500.000
    return random.randint(1_000, 1_500_000)


def random_universe():
    return random.choice(["U6", "U7", "U11"])


def generate_fake_log(timestamp):
    """
    Gera um único log fake no universo Dragon Ball X.
    """
    actions = [
        # Autenticação / acesso
        "ki_auth_success",
        "ki_auth_failed",
        "portal_login_success",
        "portal_login_failed",

        # CRUD de guerreiros/planetas/dragon balls
        "warrior_created",
        "warrior_updated",
        "warrior_deleted",
        "planet_registered",
        "planet_updated",
        "planet_deleted",
        "dragonball_collected",
        "dragonball_lost",

        # Eventos especiais
        "transformation_unlocked",
        "power_level_scanned",
        "tournament_match_created",
        "tournament_match_finished",
    ]

    action = random.choice(actions)
    user = random_warrior()
    ip = random_ip()
    resource = random_resource()
    universe = random_universe()
    power_level = random_power_level()

    status = "success"
    http_status = 200

    # Regras simples de sucesso/erro
    if action in ["ki_auth_failed", "portal_login_failed", "dragonball_lost"]:
        status = "failure"
        http_status = random.choice([401, 403, 404])

    if action in ["warrior_created", "warrior_updated", "warrior_deleted",
                  "planet_registered", "planet_updated", "planet_deleted",
                  "dragonball_collected", "tournament_match_created",
                  "tournament_match_finished", "transformation_unlocked"]:
        http_status = random.choice([200, 201, 204, 400, 409, 500])
        status = "success" if http_status < 400 else "failure"

    # Info extra específica de alguns eventos
    extra = {}

    if "transformation_unlocked" in action:
        extra["transformation"] = random.choice(
            ["kaioken", "ssj", "ssj2", "ssj3", "ssjg", "ssjb", "ultra_instinct"]
        )

    if "tournament_match" in action:
        extra["arena"] = random.choice(
            ["world_martial_arts", "universe_survival", "otherworld_tournament"]
        )
        extra["ring_out"] = random.choice([True, False])

    if "dragonball_" in action:
        extra["dragonball_number"] = random.randint(1, 7)

    # Monta o log
    log = {
        "timestamp": timestamp.isoformat(),
        "user": user,
        "action": action,
        "status": status,
        "ip": ip,
        "resource": resource,
        "http_status": http_status,
        "universe": universe,
        "power_level": power_level,
        "details": {
            "power_level_scouter": random_power_level(),
            "request_id": "".join(
                random.choices(string.ascii_lowercase + string.digits, k=12)
            ),
            "user_agent": random.choice(
                [
                    "Scouter/1.0",
                    "CapsuleCorpRadar/2.3",
                    "KiScanner/7.0",
                    "HyperbolicTimeChamberClient/9.1",
                ]
            ),
            **extra
        },
    }

    return log


def populate_initial_logs(num_logs=500):
    """
    Popula a lista LOGS com logs distribuídos nas últimas 24 horas.
    """
    global LOGS
    LOGS = []

    now = datetime.now(timezone.utc)

    for _ in range(num_logs):
        # espalha os logs aleatoriamente nas últimas 24h
        delta_minutes = random.randint(0, 24 * 60)
        ts = now - timedelta(minutes=delta_minutes)
        LOGS.append(generate_fake_log(ts))

    # ordena por timestamp (mais antigos primeiro)
    LOGS.sort(key=lambda l: l["timestamp"], reverse=False)


# ----- PARSE DE PARÂMETROS ----- #

def parse_last_param(last_value):
    """
    Converte o parâmetro last (ex: '15min', '1h') em um timedelta.
    Suporta:
      - Xmin (minutos)
      - Xh (horas)
    """
    if not last_value:
        return None

    try:
        if last_value.endswith("min"):
            amount = int(last_value[:-3])
            return timedelta(minutes=amount)
        elif last_value.endswith("h"):
            amount = int(last_value[:-1])
            return timedelta(hours=amount)
        else:
            # formato não suportado
            return None
    except ValueError:
        return None


# ----- ENDPOINT /audit ----- #

@app.route("/audit", methods=["GET"])
def get_audit_logs():
    """
    Endpoint para retornar logs de auditoria Dragon Ball X.

    Exemplos:
    - /audit                    -> todos os logs (limit padrão)
    - /audit?last=15min         -> últimos 15 minutos
    - /audit?last=1h            -> última 1 hora
    - /audit?limit=50           -> limita a 50 registros
    - /audit?last=1h&limit=100  -> combina filtro de tempo + limite
    """
    last_param = request.args.get("last")
    limit_param = request.args.get("limit", default="100")

    # interpreta o limit
    try:
        limit = int(limit_param)
    except ValueError:
        limit = 100

    # filtra por tempo, se last foi informado
    time_delta = parse_last_param(last_param)
    filtered_logs = LOGS

    if time_delta is not None:
        now = datetime.now(timezone.utc)
        threshold = now - time_delta

        def is_recent(log):
            ts = datetime.fromisoformat(log["timestamp"])
            # garante que o timestamp tenha timezone; se não tiver, assume UTC
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts >= threshold

        filtered_logs = list(filter(is_recent, LOGS))

    # ordena do mais recente para o mais antigo
    filtered_logs.sort(key=lambda l: l["timestamp"], reverse=True)

    # aplica limite
    result = filtered_logs[:limit]

    return jsonify(result)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="API de auditoria Dragon Ball X")
    parser.add_argument("--port", type=int, default=5000, help="Porta para subir o Flask")
    parser.add_argument("--debug", action="store_true", help="Ativa modo debug do Flask")
    args = parser.parse_args()

    populate_initial_logs()
    # debug=True só para laboratório; em produção, remover ou controlar via flag
    app.run(host="0.0.0.0", port=args.port, debug=args.debug)
