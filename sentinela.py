import threading
import time
import logging
import json
import os
from collections import defaultdict
from scapy.all import sniff, IP
from flask import Flask
from flask_socketio import SocketIO

# Configuração da pasta de buffer
BUFFER = "/tmp/traffic_buffer"
os.makedirs(BUFFER, exist_ok=True)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

IP_STATE = defaultdict(lambda: {"bytes": 0, "requests": 0, "risk": 0.0, "last_seen": 0})
IP_BANNED = set()
WHITELIST = {"127.0.0.1", "192.168.1.1"}

logging.basicConfig(filename="sentinela.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def log(msg):
    print(msg)
    logging.info(msg)
    socketio.emit("log", msg)

def calcular_risco(ip, size):
    state = IP_STATE[ip]
    state["bytes"] += size
    state["requests"] += 1
    state["last_seen"] = time.time()
    risk = state["risk"]
    if size > 1000: risk += 0.2
    if state["requests"] > 50: risk += 0.3
    if state["bytes"] > 50000: risk += 0.2
    risk = min(risk, 1.0)
    state["risk"] = risk
    return risk

def packet_callback(packet):
    if IP not in packet: return
    ip = packet[IP].src
    size = len(packet)
    if ip in WHITELIST or ip in IP_BANNED: return

    risk = calcular_risco(ip, size)
    event = {"ip": ip, "size": size, "risk": risk, "summary": packet.summary(), "time": time.time()}
    
    # Salva no buffer para a IA ler
    event_file = os.path.join(BUFFER, f"event_{int(time.time()*1000)}_{ip.replace('.', '_')}.json")
    with open(event_file, "w") as f:
        json.dump(event, f)

    log(f"[EVENT] {ip} | {size}B | RISK {risk:.2f}")
    socketio.emit("event", event)

def feedback_loop():
    while True:
        try:
            if os.path.exists("feedback_ban.log"):
                with open("feedback_ban.log", "r") as f:
                    for line in f:
                        ip = line.strip()
                        if ip:
                            IP_BANNED.add(ip)
                            log(f"[BAN] {ip}")
                open("feedback_ban.log", "w").close()
        except: pass
        time.sleep(2)

if __name__ == "__main__":
    threading.Thread(target=feedback_loop, daemon=True).start()
    threading.Thread(target=lambda: sniff(filter="ip", prn=packet_callback, store=False), daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=5000)
