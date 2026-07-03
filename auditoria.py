import os
import re
import time
import requests
import subprocess
from collections import defaultdict, deque

# Configurações
LOG_FILE = "/home/kali/pentest_lab/monitoramento_rede.log"
MODELO = "qwen2.5:3b"
SCORE_THRESHOLD = 3
PALAVRAS_SUSPEITAS = ["select", "union", "or 1=1", "script", "etc/passwd", "alert", "drop"]

# Memória
historico_por_ip = defaultdict(lambda: deque(maxlen=6))
risk_score = defaultdict(int)
IP_VOLUME_HISTORY = defaultdict(int)
ultimos_vereditos = deque(maxlen=10) # Armazena os últimos 10 alertas
ULTIMA_RENDERIZACAO = 0

def get_gpu_temp():
    try:
        return subprocess.check_output(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader"]).decode("utf-8").strip()
    except: return "N/A"

def analisar_com_ia(linha, ip):
    payload_match = re.search(r'PAYLOAD: (.*?) \|', linha)
    conteudo = payload_match.group(1).lower() if payload_match else linha.lower()
    if not any(x in conteudo for x in PALAVRAS_SUSPEITAS): return "NORMAL"

    historico_por_ip[ip].append(conteudo)
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": MODELO, "stream": False,
        "prompt": f"Analise: {conteudo}. Responda APENAS: ATAQUE_CRITICO, ATAQUE_FLOOD ou NORMAL."
    }
    try:
        response = requests.post(url, json=payload, timeout=5)
        return response.json().get('response', 'NORMAL').strip().upper()
    except: return "NORMAL"

def renderizar_dashboard():
    global ULTIMA_RENDERIZACAO
    if (time.time() - ULTIMA_RENDERIZACAO) < 0.5: return
    ULTIMA_RENDERIZACAO = time.time()
    
    os.system('clear')
    print(f"=== MOTOR COGNITIVO IPS v11.1 | MODELO: {MODELO} ===")
    print(f"🌡 GPU: {get_gpu_temp()}°C | THRESHOLD: {SCORE_THRESHOLD}")
    print("-" * 77)
    for ip, total_bytes in list(IP_VOLUME_HISTORY.items()):
        print(f"{ip:<25} | {round(total_bytes/1024, 2):<10} KB | Risco: {risk_score[ip]}")
    print("\n📜 ÚLTIMOS VEREDITOS:")
    for v in reversed(ultimos_vereditos): print(v)

def monitorar_fila():
    with open(LOG_FILE, 'r') as f:
        f.seek(0, 2)
        while True:
            linha = f.readline()
            if not linha:
                time.sleep(0.1)
                renderizar_dashboard()
                continue
            
            ip_match = re.search(r'SRC: (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', linha)
            if ip_match:
                ip = ip_match.group(1)
                IP_VOLUME_HISTORY[ip] += int(re.search(r'SIZE: (\d+)B', linha).group(1) or 0)
                
                status = analisar_com_ia(linha, ip)
                if status == "ATAQUE_CRITICO":
                    risk_score[ip] = SCORE_THRESHOLD
                    ultimos_vereditos.append(f"🚨 CRÍTICO: {ip} | Payload Hostil!")
                elif status == "ATAQUE_FLOOD":
                    risk_score[ip] += 1
                    ultimos_vereditos.append(f"⚠ SUSPEITO: {ip} | Flood ({risk_score[ip]})")
                else:
                    risk_score[ip] = max(0, risk_score[ip] - 1)
                    ultimos_vereditos.append(f"✅ NORMAL: {ip}")

if __name__ == "__main__":
    monitorar_fila()
