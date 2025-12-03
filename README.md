# fakeLogs

Scripts em Python para geração de **logs falsos (fake)** — úteis para testes, simulações, estudo de análise de logs, pipelines de SIEM, SOC, e validação de parsing.
Os arquivos geram eventos artificiais, incluindo acessos normais, falhas de login, brute force, tentativas maliciosas e outros comportamentos que imitam ambientes reais.

Este repositório foi criado e expandido com auxílio de **IA**.

---

### 📌 O que esses scripts fazem?

* Geram logs de forma contínua ou limitada por quantidade
* Podem imprimir no terminal, salvar em arquivo ou enviar por TCP/UDP
* Criam tráfego de log realista para desenvolvimento, aprendizagem e testes

---

### Como usar de maneira centralizada com o `fakeLogs.py`

```bash
python3 fakeLogs.py --ssh udp:<ip>:<port> --firewall udp:<ip>:<port> --apache <ip>:<port>
```

Parâmetros disponíveis:

| Flag                 | Função                              |
| -------------------- | ----------------------------------- |
| `--application porta`      | Sobe uma aplicação que gera logs CRUD fakes em `/audit`, possivel obter via GET, exemplo `GET /audit?last=15min` |
| `--ssh`              | Gera logs SSH                       |
| `--fortigate`        | Gera logs do Firewall fortigate     |
| `--apache`           | Gera logs do apache                 |
| `--tcp ip:porta`     | Enviar logs via TCP                 |
| `--udp ip:porta`     | Enviar logs via UDP                 |
| `--file caminho.log` | Salvar logs em arquivo              |
| `--seed N`           | Geração fixa e repetível (opcional) |

### Como usar os scripts de maneira individual

```bash
python <script>.py --count 100 --interval 0.5
python <script>.py --file output.log
python <script>.py --udp 192.168.0.10:514
python <script>.py --count 0 --interval 1       # infinito (Ctrl+C para parar)
python application.py --port 8080               # Sobe a aplicação na porta 8080
```

Parâmetros disponíveis:

| Flag                 | Função                              |
| -------------------- | ----------------------------------- |
| `--count N`          | Quantidade de linhas (0 = infinito) |
| `--interval S`       | Intervalo entre geração de logs     |
| `--file caminho.log` | Salvar logs em arquivo              |
| `--tcp ip:porta`     | Enviar logs via TCP                 |
| `--udp ip:porta`     | Enviar logs via UDP                 |
| `--seed N`           | Geração fixa e repetível (opcional) |

---

### Observação

Este projeto foi criado com suporte de **Inteligência Artificial**, permitindo geração flexível e personalizável de cenários simulados.

