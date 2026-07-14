<<<<<<< HEAD
import threading
import time
import logging
from scapy.all import sniff, IP

# Caminho deve coincidir com o LOG_FILE do auditoria7.py
LOG_FILE = "/home/kali/pentest_lab/monitoramento_rede.log"

def log_para_auditoria(ip, size, payload):
    # Formato esperado pelo auditoria7.py: SRC: <ip> | SIZE: <size>B | PAYLOAD: <payload>
    msg = f"SRC: {ip} | SIZE: {size}B | PAYLOAD: {payload}"
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def packet_callback(packet):
    if IP in packet:
        ip = packet[IP].src
        size = len(packet)
        # Extrai resumo do payload para a IA analisar
        payload = packet.summary() 
        log_para_auditoria(ip, size, payload)

if __name__ == "__main__":
    print("[*] Sentinela V3 (Modo Integrado) rodando...")
    # Garante que o arquivo existe
    open(LOG_FILE, 'a').close()
    sniff(filter="ip", prn=packet_callback, store=False)
=======
from scapy.all import sniff, IP, TCP
import os

LOG_FILE = "/home/kali/pentest_lab/monitoramento_rede.log"
WHITELIST = ["192.168.1.5", "192.168.1.86"]

def log_para_auditoria(ip, size, payload):
    # Whitelist aplicada antes de escrever no log
    if ip in WHITELIST: return
    
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"SRC: {ip} | SIZE: {size}B | PAYLOAD: {payload}\n")
    except Exception as e:
        print(f"Erro ao logar: {e}")

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP].src
        # Filtro de Whitelist no nível de callback
        if ip in WHITELIST: return
        
        size = len(packet)
        # Extrai resumo do payload de forma segura
        payload = str(packet[TCP].payload)[:100] 
        log_para_auditoria(ip, size, payload)

if __name__ == "__main__":
    # Garante o ambiente
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    open(LOG_FILE, 'a').close()
    
    print("[*] Sentinela V4 (Whitelisted) rodando...")
    print(f"[*] Protegendo: {WHITELIST}")
    
    # Sniff em tráfego TCP na interface principal
    try:
        sniff(filter="tcp", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sentinela parada pelo operador.")
>>>>>>> 4877218 (Commit da Sentinela: versão melhorada de monitoramento e defesa)
