import os
import time
import json
import requests

BUFFER = "/tmp/traffic_buffer"
MODEL = "qwen2.5-coder:3b"

# =========================
# IA ENGINE
# =========================

def analisar(event):
    prompt = f"""
Você é um sistema SOC.

Classifique o evento:

Responda APENAS JSON:

{{
  "tipo": "NORMAL ou ATAQUE",
  "categoria": "tipo de ataque",
  "confianca": 0.0-1.0,
  "risco": 0.0-1.0
}}

Evento:
{json.dumps(event)}
"""

    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=15
        )

        raw = r.json().get("response", "")

        try:
            return json.loads(raw)
        except:
            return {
                "tipo": "ERRO",
                "raw": raw
            }

    except Exception as e:
        return {"tipo": "ERRO", "error": str(e)}

# =========================
# PROCESS
# =========================

def process(path):
    try:
        with open(path) as f:
            event = json.load(f)

        result = analisar(event)

        print("\n[IA]", event["ip"], "=>", result)

        # decisão de bloqueio
        if result.get("tipo") == "ATAQUE" or result.get("risco", 0) > 0.7:
            with open("feedback_ban.log", "a") as f:
                f.write(event["ip"] + "\n")

            print("[!] BAN ENVIADO:", event["ip"])

    except Exception as e:
        print("[ERRO]", e)

    finally:
        try:
            os.remove(path)
        except:
            pass

# =========================
# LOOP
# =========================

def run():
    os.makedirs(BUFFER, exist_ok=True)

    print("[*] IA V2 rodando...")

    seen = set()

    while True:
        for file in os.listdir(BUFFER):
            path = os.path.join(BUFFER, file)

            if path in seen:
                continue

            process(path)
            seen.add(path)

        time.sleep(1)

if __name__ == "__main__":
    run()
