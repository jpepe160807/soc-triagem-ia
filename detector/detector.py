"""
Detector de força bruta em logs SSH.

Lê um arquivo de log de autenticação do Linux (ex.: /var/log/auth.log),
encontra IPs com muitas tentativas de login que falharam e envia cada
alerta para o webhook do n8n, que faz a triagem com IA.

Uso:
    python detector.py exemplo_auth.log --dry-run
    python detector.py exemplo_auth.log --webhook http://localhost:5678/webhook/alerta-soc

Só usa a biblioteca padrão do Python (não precisa instalar nada).
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict

# Quantas falhas do mesmo IP viram um alerta
LIMITE_FALHAS = 5

# Expressões regulares que reconhecem as linhas do sshd que interessam
RE_FALHA = re.compile(
    r"^(?P<data>\w{3}\s+\d+\s[\d:]+)\s(?P<host>\S+)\ssshd\[\d+\]:\s"
    r"Failed password for (?:invalid user )?(?P<usuario>\S+) from (?P<ip>[\d.]+)"
)
RE_SUCESSO = re.compile(
    r"^(?P<data>\w{3}\s+\d+\s[\d:]+)\s(?P<host>\S+)\ssshd\[\d+\]:\s"
    r"Accepted \S+ for (?P<usuario>\S+) from (?P<ip>[\d.]+)"
)


def ler_log(caminho):
    """Lê o log e agrupa as falhas e os sucessos por IP."""
    por_ip = defaultdict(lambda: {"falhas": [], "sucessos": [], "linhas": []})

    with open(caminho, encoding="utf-8", errors="replace") as arquivo:
        for numero, linha in enumerate(arquivo):
            linha = linha.strip()
            falha = RE_FALHA.match(linha)
            sucesso = RE_SUCESSO.match(linha)
            evento = falha or sucesso
            if not evento:
                continue

            dados = por_ip[evento["ip"]]
            dados["host"] = evento["host"]
            dados["linhas"].append(linha)
            registro = {"data": evento["data"], "usuario": evento["usuario"], "ordem": numero}
            if falha:
                dados["falhas"].append(registro)
            else:
                dados["sucessos"].append(registro)

    return por_ip


def gerar_alertas(por_ip):
    """Cria um alerta para cada IP que passou do limite de falhas."""
    alertas = []
    for ip, dados in por_ip.items():
        falhas = dados["falhas"]
        if len(falhas) < LIMITE_FALHAS:
            continue

        # Login que deu certo DEPOIS das falhas = possível senha descoberta
        ultima_falha = falhas[-1]
        sucesso_depois = [s for s in dados["sucessos"] if s["ordem"] > ultima_falha["ordem"]]

        alertas.append({
            "tipo": "forca_bruta_ssh",
            "host": dados["host"],
            "ip_origem": ip,
            "tentativas_falhas": len(falhas),
            "usuarios_alvo": sorted({f["usuario"] for f in falhas}),
            "primeira_tentativa": falhas[0]["data"],
            "ultima_tentativa": ultima_falha["data"],
            "login_com_sucesso_depois": bool(sucesso_depois),
            "usuario_que_entrou": sucesso_depois[0]["usuario"] if sucesso_depois else None,
            "amostra_log": dados["linhas"][-5:],  # só as últimas linhas, para não mandar o log inteiro
        })
    return alertas


def enviar(alerta, url):
    """Envia o alerta para o n8n e devolve a resposta (a triagem feita pela IA)."""
    corpo = json.dumps(alerta).encode("utf-8")
    pedido = urllib.request.Request(
        url, data=corpo, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(pedido, timeout=120) as resposta:
        return json.loads(resposta.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Detecta força bruta SSH e envia alertas ao n8n.")
    parser.add_argument("log", help="caminho do arquivo de log (ex.: exemplo_auth.log)")
    parser.add_argument("--webhook", help="URL do webhook do n8n")
    parser.add_argument("--dry-run", action="store_true", help="só mostra os alertas, sem enviar")
    args = parser.parse_args()

    alertas = gerar_alertas(ler_log(args.log))
    print(f"{len(alertas)} alerta(s) encontrado(s).\n")

    for alerta in alertas:
        print(f"-> {alerta['ip_origem']}: {alerta['tentativas_falhas']} falhas "
              f"(sucesso depois: {'sim' if alerta['login_com_sucesso_depois'] else 'não'})")

        if args.dry_run or not args.webhook:
            print(json.dumps(alerta, indent=2, ensure_ascii=False))
            continue

        try:
            triagem = enviar(alerta, args.webhook)
        except urllib.error.URLError as erro:
            print(f"   Erro ao enviar para o n8n: {erro}", file=sys.stderr)
            continue

        print(f"   Severidade: {triagem.get('severidade')} | Escalar: {triagem.get('escalar')}")
        print(f"   Resumo da IA: {triagem.get('resumo')}\n")


if __name__ == "__main__":
    main()
