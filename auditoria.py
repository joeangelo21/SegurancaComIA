import os
import re
import time
import requests
import subprocess
from collections import defaultdict, deque

# Configurações
LOG_FILE = "monitoramento_rede.log"
FEEDBACK_FILE = "feedback_ban.log"
MODELO = "qwen2.5:3b"
PALAVRAS_SUSPEITAS = ["select", "union", "script", "etc/passwd", "drop", "alert"]

# Memória
historico_por_ip = defaultdict(lambda: deque(maxlen=6))
IP_VOLUME_HISTORY = defaultdict(int)
ultimos_vereditos = []
ULTIMA_RENDERIZACAO = 0

def get_gpu_temp():
    try:
        return subprocess.check_output(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader"]).decode("utf-8").strip()
    except: return "N/A"

def bloquear_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        with open(FEEDBACK_FILE, "a") as f: f.write(f"{ip}\n")
    except: pass

def renderizar_dashboard(ip_recent, status):
    global ULTIMA_RENDERIZACAO
    if (time.time() - ULTIMA_RENDERIZACAO) < 0.5: return
    ULTIMA_RENDERIZACAO = time.time()
    
    os.system('clear')
    print(f"=== MOTOR COGNITIVO IPS [CÉREBRO ATIVO] | MODELO: {MODELO} ===")
    print(f"🌡 GPU: {get_gpu_temp()}°C | MONITORANDO LOGS...")
    print("-" * 77)
    print(f"Último IP processado: {ip_recent} | Status: {status}")
    print("\n📜 MURAL DE VEREDITOS (IA):")
    if ultimos_vereditos: print("\n".join(reversed(ultimos_vereditos)))

def analisar_com_ia(linha, ip):
    payload_match = re.search(r'PAYLOAD: (.*?) \| TIME:', linha)
    conteudo = payload_match.group(1).lower() if payload_match else linha.lower()

    if not any(x in conteudo for x in PALAVRAS_SUSPEITAS): return "NORMAL"

    historico_por_ip[ip].append(conteudo)
    try:
        response = requests.post("http://localhost:11434/api/generate", json={
            "model": MODELO, "stream": False, "prompt": f"Analise: {conteudo}. Responda APENAS: ATAQUE ou NORMAL."
        }, timeout=5)
        return response.json().get('response', 'NORMAL').strip().upper()
    except: return "NORMAL"

def processar():
    print(f"[*] Cérebro Cognitivo online. Aguardando fatos do Sentinela...")
    with open(LOG_FILE, 'r') as f:
        f.seek(0, 2)
        while True:
            linha = f.readline()
            if not linha:
                time.sleep(0.1)
                continue
            
            ip_match = re.search(r'SRC: (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)', linha)
            if ip_match:
                ip = ip_match.group(1)
                classificacao = analisar_com_ia(linha, ip)
                
                msg = f"[{time.strftime('%H:%M:%S')}] {classificacao}: {ip}"
                ultimos_vereditos.append(msg)
                if len(ultimos_vereditos) > 8: ultimos_vereditos.pop(0)

                if classificacao == "ATAQUE":
                    bloquear_ip(ip)
                
                renderizar_dashboard(ip, classificacao)

if __name__ == "__main__":
    processar()
