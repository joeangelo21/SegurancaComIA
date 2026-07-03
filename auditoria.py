import os
import time
import json
import requests

BUFFER = "/tmp/traffic_buffer"
MODEL = "qwen2.5-coder:3b"

def analisar(event):
    prompt = f"""
Você é um sistema SOC. Classifique o evento:
Responda APENAS JSON (sem texto adicional ou markdown):
{json.dumps(event)}
"""
    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=30  # Timeout maior para não falhar com carga alta
        )

        raw = r.json().get("response", "").strip()
        
        # Limpa blocos markdown que o modelo pode inserir
        if "```" in raw:
            raw = raw.replace("```json", "").replace("```", "").strip()

        try:
            return json.loads(raw)
        except:
            return {"tipo": "ERRO", "raw": raw}
    except Exception as e:
        return {"tipo": "ERRO", "error": str(e)}

def process(path):
    try:
        with open(path) as f:
            event = json.load(f)
        result = analisar(event)
        print("\n[IA]", event["ip"], "=>", result)

        if result.get("tipo") == "ATAQUE" or result.get("risco", 0) > 0.7:
            with open("feedback_ban.log", "a") as f:
                f.write(event["ip"] + "\n")
            print("[!] BAN ENVIADO:", event["ip"])
    except Exception as e:
        print("[ERRO]", e)
    finally:
        try: os.remove(path)
        except: pass

def run():
    print("[*] IA V2 rodando...")
    while True:
        files = [os.path.join(BUFFER, f) for f in os.listdir(BUFFER)]
        for path in files:
            process(path)
        time.sleep(1)

if __name__ == "__main__":
    run()
