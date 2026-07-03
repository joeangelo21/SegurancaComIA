import threading
import time
import json
import logging
from collections import defaultdict
from scapy.all import sniff, IP

from flask_socketio import SocketIO
from flask import Flask

# =========================
# CONFIG
# =========================

WHITELIST = {"127.0.0.1", "192.168.1.1"}
IP_BANNED = set()
IP_VOLUME = defaultdict(int)

LOG_FILE = "sentinela.log"

# =========================
# APP SOCKET (DASHBOARD BACKEND)
# =========================

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# =========================
# LOG
# =========================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def log(msg):
    print(msg)
    logging.info(msg)
    socketio.emit("log", msg)

# =========================
# VALIDATION
# =========================

def valid_ip(ip):
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except:
        return False

# =========================
# PACKET HANDLER
# =========================

def packet_callback(packet):
    if IP not in packet:
        return

    ip_src = packet[IP].src
    size = len(packet)

    if not valid_ip(ip_src):
        return

    if ip_src in WHITELIST or ip_src in IP_BANNED:
        return

    IP_VOLUME[ip_src] += size

    event = {
        "ip": ip_src,
        "size": size,
        "summary": packet.summary(),
        "total": IP_VOLUME[ip_src],
        "time": time.time()
    }

    log(f"[EVENT] {ip_src} {size} bytes")

    socketio.emit("event", event)

# =========================
# FEEDBACK LOOP
# =========================

def feedback_loop():
    while True:
        try:
            with open("feedback_ban.log", "r") as f:
                for line in f:
                    ip = line.strip()
                    if valid_ip(ip):
                        IP_BANNED.add(ip)
                        log(f"[BAN] {ip}")
            open("feedback_ban.log", "w").close()
        except:
            pass

        time.sleep(2)

# =========================
# DASHBOARD PAGE
# =========================

@app.route("/")
def index():
    return """
    <html>
    <head>
        <title>Sentinela SOC</title>
        <style>
            body { background:#0d0f14; color:#0f0; font-family:monospace; }
            .box { display:flex; gap:20px; }
            .panel { width:50%; border:1px solid #0f0; padding:10px; }
        </style>
    </head>
    <body>
        <h1>🛡️ SENTINELA LIVE</h1>

        <div class="box">
            <div class="panel">
                <h2>EVENTOS</h2>
                <ul id="events"></ul>
            </div>

            <div class="panel">
                <h2>LOGS</h2>
                <ul id="logs"></ul>
            </div>
        </div>

        <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
        <script>
            const socket = io();

            socket.on("event", data => {
                let li = document.createElement("li");
                li.innerHTML = data.ip + " | " + data.size + " bytes | total: " + data.total;
                document.getElementById("events").prepend(li);
            });

            socket.on("log", data => {
                let li = document.createElement("li");
                li.innerHTML = data;
                document.getElementById("logs").prepend(li);
            });
        </script>
    </body>
    </html>
    """

# =========================
# START
# =========================

def start_sniffer():
    log("[*] Sentinela rodando...")
    sniff(filter="ip", prn=packet_callback, store=False)

if __name__ == "__main__":
    threading.Thread(target=feedback_loop, daemon=True).start()
    threading.Thread(target=start_sniffer, daemon=True).start()

    socketio.run(app, host="0.0.0.0", port=5000)
