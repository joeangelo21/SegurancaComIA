import os
import time
import requests

WATCH_DIR = "/tmp/traffic_buffer"
MODELO = "qwen2.5-coder:3b"

def analisar_trafego(payload):
    prompt = (
        "Você é um motor de inspeção de tráfego de rede. "
        "Classifique o payload como ATAQUE (XSS, SQLi, Exploit) ou NORMAL. "
        "Responda apenas 'ATAQUE: tipo' ou 'NORMAL'.\n\n"
        f"Payload:\n{payload}"
    )

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODELO,
                "stream": False,
                "prompt": prompt
            },
            timeout=10
        )

        data = r.json()
        return data.get("response", "NORMAL")

    except Exception as e:
        print(f"[ERRO IA] {e}")
        return "ERRO_IA"


def processar_arquivo(caminho):
    try:
        with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
            payload = f.read().strip()

        if not payload:
            return

        veredito = analisar_trafego(payload)
        nome = os.path.basename(caminho)

        print(f"[*] {nome} -> {veredito}")

        if "ATAQUE" in veredito:
            print(f"[!] ALERTA: possível ataque detectado em {nome}")

    finally:
        # só remove depois de tentar processar
        if os.path.exists(caminho):
            os.remove(caminho)


def monitorar():
    os.makedirs(WATCH_DIR, exist_ok=True)

    print(f"[*] Sentinela ativo em {WATCH_DIR}")

    vistos = set()

    while True:
        try:
            arquivos = os.listdir(WATCH_DIR)

            for arq in arquivos:
                caminho = os.path.join(WATCH_DIR, arq)

                if caminho in vistos:
                    continue

                processar_arquivo(caminho)
                vistos.add(caminho)

        except Exception as e:
            print(f"[ERRO LOOP] {e}")

        time.sleep(1)


if __name__ == "__main__":
    monitorar()
