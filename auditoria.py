import os
import re
import time
import requests
import subprocess
from collections import defaultdict, deque

# ==============================================================================
# CONFIGURAÇÕES E MEMÓRIA
# ==============================================================================
LOG_FILE = "/home/kali/pentest_lab/monitoramento_rede.log"
MODELO = "qwen2.5-coder:3b"
URL_OLLAMA = "http://localhost:11434/api/generate"
SCORE_THRESHOLD = 3
PALAVRAS_SUSPEITAS = ["select", "union", "or 1=1", "script", "etc/passwd", "alert", "drop"]

historico_por_ip = defaultdict(lambda: deque(maxlen=6))
risk_score = defaultdict(int)
IP_VOLUME_HISTORY = defaultdict(int)
ultimos_vereditos = deque(maxlen=10)
ULTIMA_RENDERIZACAO = 0

# ==============================================================================
# MÓDULOS DE SUPORTE E IA
# ==============================================================================
def verificar_modelo():
    """Força o carregamento do modelo na RAM antes de iniciar o monitoramento"""
    try:
        requests.post(URL_OLLAMA, json={"model": MODELO, "prompt": "oi", "stream": False}, timeout=60)
        return True
    except: return False

def get_gpu_temp():
    try:
        return subprocess.check_output(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader"]).decode("utf-8").strip()
    except: return "N/A"

def analisar_com_ia(linha, ip):
    payload_match = re.search(r'PAYLOAD: (.*?) \|', linha)
    conteudo = payload_match.group(1).lower() if payload_match else linha.lower()
    if not any(x in conteudo for x in PALAVRAS_SUSPEITAS): return "NORMAL"

    try:
        payload = {
            "model": MODELO, "stream": False,
            "prompt": f"Analise: {conteudo}. Responda APENAS: ATAQUE_CRITICO, ATAQUE_FLOOD ou NORMAL."
        }
        response = requests.post(URL_OLLAMA, json=payload, timeout=30)
        return response.json().get('response', 'NORMAL').strip().upper()
    except: return "NORMAL"

def renderizar_dashboard():
    global ULTIMA_RENDERIZACAO
    if (time.time() - ULTIMA_RENDERIZACAO) < 0.5: return
    ULTIMA_RENDERIZACAO = time.time()
    
    output = [
        f"=== MOTOR COGNITIVO IPS v11.1 (ESTÁVEL) | MODELO: {MODELO} ===",
        f"🌡 GPU: {get_gpu_temp()}°C | THRESHOLD: {SCORE_THRESHOLD}",
        "-" * 77
    ]
    for ip, total_bytes in list(IP_VOLUME_HISTORY.items()):
        output.append(f"{ip:<25} | {round(total_bytes/1024, 2):<10} KB | Risco: {risk_score[ip]}")
    output.append("\n📜 ÚLTIMOS VEREDITOS:")
    for v in reversed(list(ultimos_vereditos)): output.append(v)
    
    print("\033[H" + "\n".join(output) + "\033[J", end="")

# ==============================================================================
# LOOP PRINCIPAL
# ==============================================================================
def monitorar_fila():
    if not os.path.exists(LOG_FILE): open(LOG_FILE, 'a').close()
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
                size_match = re.search(r'SIZE: (\d+)B', linha)
                IP_VOLUME_HISTORY[ip] += int(size_match.group(1)) if size_match else 0
                
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
            renderizar_dashboard()

if __name__ == "__main__":
    if verificar_modelo():
        print("\033[2J", end="")
        monitorar_fila()
    else:
        print("Erro: Ollama não respondeu ao aquecimento. Verifique o serviço.")
