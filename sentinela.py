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
