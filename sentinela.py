import os
from scapy.all import sniff, IP, TCP

# Caminho deve coincidir com o LOG_FILE do auditoria7.py (mesma pasta)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "monitoramento_rede.log")
WHITELIST = ["192.168.1.5", "192.168.1.86"]

def log_para_auditoria(ip, size, payload):
    if ip in WHITELIST:
        return
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"SRC: {ip} | SIZE: {size}B | PAYLOAD: {payload}\n")
    except Exception as e:
        print(f"Erro ao logar: {e}")

def packet_callback(packet):
    if IP not in packet:
        return

    ip = packet[IP].src
    if ip in WHITELIST:
        return

    size = len(packet)

    # Se for TCP com payload, extrai um resumo seguro do conteúdo;
    # caso contrário usa o resumo padrão do pacote (cobre UDP/ICMP/etc.)
    if TCP in packet and bytes(packet[TCP].payload):
        payload = str(bytes(packet[TCP].payload))[:100]
    else:
        payload = packet.summary()

    log_para_auditoria(ip, size, payload)

if __name__ == "__main__":
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    open(LOG_FILE, 'a').close()

    print("[*] Sentinela rodando...")
    print(f"[*] Protegendo: {WHITELIST}")

    try:
        sniff(filter="ip", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sentinela parada pelo operador.")
