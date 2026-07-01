import threading
import time
import os
import logging
from collections import defaultdict, deque
from scapy.all import sniff, IP

# Configurações
LOG_FILE = "monitoramento_rede.log"
FEEDBACK_FILE = "feedback_ban.log"
WHITELIST = {"127.0.0.1", "192.168.1.1", "192.168.1.5"}

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(message)s')

IP_BANNED = set()
IP_VOLUME_HISTORY = defaultdict(lambda: {"total": 0, "last_seen": time.time()})
data_lock = threading.Lock()

def monitorar_feedback():
    """Escuta o Cérebro para atualizar bloqueios locais."""
    while True:
        if os.path.exists(FEEDBACK_FILE):
            with open(FEEDBACK_FILE, "r") as f:
                for line in f:
                    IP_BANNED.add(line.strip())
            os.remove(FEEDBACK_FILE)
        time.sleep(2)

def packet_callback(packet):
    try:
        if IP in packet:
            ip_src = packet[IP].src
            if ip_src in WHITELIST or ip_src in IP_BANNED:
                return
            
            with data_lock:
                size = len(packet)
                # Formato que o Cérebro (IA) entende perfeitamente
                msg = f"SRC: {ip_src} | SIZE: {size}B | PAYLOAD: {packet.summary()} | TIME: {time.time()}"
                logging.info(msg)
                IP_VOLUME_HISTORY[ip_src]["total"] += size
    except: pass

if __name__ == "__main__":
    threading.Thread(target=monitorar_feedback, daemon=True).start()
    print("[*] Sentinela ativo. Enviando fatos para o Cérebro...")
    sniff(filter="ip", prn=packet_callback, store=False)
