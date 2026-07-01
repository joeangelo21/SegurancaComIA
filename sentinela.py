import threading
import time
import os
from queue import Queue
from collections import defaultdict, deque
import logging
from scapy.all import sniff, IP, TCP, Raw

# ==========================
# CONFIGURAÇÕES (MODO LOCAL)
# ==========================
LOG_FILE = "monitoramento_rede.log"
TEMP_LOG = "telemetria.log"

# Lista branca genérica para não banir o próprio sistema
WHITELIST = {"127.0.0.1", "192.168.1.1", "192.168.1.5"}

# Limites de detecção
PORT_SCAN_LIMIT = 20
PORT_SCAN_WINDOW = 30
PAYLOAD_MAX_BYTES = 500

log_queue = Queue()
IP_BANNED = set()
IP_VOLUME_HISTORY = defaultdict(lambda: {"total": 0})
PORT_SCAN_TRACKER = defaultdict(deque)
data_lock = threading.Lock()
logs_conexao = deque(maxlen=10)

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        if ip_src in WHITELIST:
            return
        
        with data_lock:
            IP_VOLUME_HISTORY[ip_src]["total"] += len(packet)
            logs_conexao.append(f"Atividade detectada de: {ip_src}")

# Inicia a captura
def iniciar_sniff():
    sniff(filter="ip", prn=packet_callback, store=False)

def analyzer():
    while True:
        time.sleep(3)
        with data_lock:
            snapshot = dict(IP_VOLUME_HISTORY)
            exibicao = list(logs_conexao)
            
        print("\033[H\033[J", end="") 
        print("=================================================")
        print(f"               SENTINELA v3.1 LOCAL             ")
        print("=================================================")
        print(f"{'IP Remetente':<25} {'Tráfego (KB)'}")
        print("-" * 50)
        
        for ip, dados in snapshot.items():
            print(f"{ip:<25} {round(dados['total'] / 1024, 2)} KB")
            
        print("\n[MURAL DE EVENTOS EM TEMPO REAL]")
        print("-" * 50)
        for _linha in exibicao: print(_linha)

if __name__ == "__main__":
    t1 = threading.Thread(target=iniciar_sniff, daemon=True)
    t1.start()
    analyzer()
