import threading
import time
import logging
from collections import defaultdict
from scapy.all import sniff, IP

from flask import Flask
from flask_socketio import SocketIO

# =========================
# APP (DASHBOARD BACKEND)
# =========================

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# =========================
# STATE (SOC MEMORY)
# =========================

IP_STATE = defaultdict(lambda: {
    "bytes": 0,
    "requests": 0,
    "risk": 0.0,
    "last_seen": 0
})

IP_BANNED = set()

WHITELIST = {"127.0.0.1", "192.168.1.1"}

# =========================
# LOG
# =========================

logging.basicConfig(
    filename="sentinela.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def log(msg):
    print(msg)
    logging.info(msg)
    socketio.emit("log", msg)

# =========================
# RISK ENGINE
# =========================

def calcular_risco(ip, size):
    state = IP_STATE[ip]

    state["bytes"] += size
    state["requests"] += 1
    state["last_seen"] = time.time()

    risk = state["risk"]

    if size > 1000:
        risk += 0.2

    if state["requests"] > 50:
        risk += 0.3

    if state["bytes"] > 50000:
        risk += 0.2

    if risk > 1:
        risk = 1

    state["risk"] = risk
    return risk

# =========================
# PACKET HANDLER
# =========================

def packet_callback(packet):
    if IP not in packet:
        return

    ip = packet[IP].src
    size = len(packet)

    if ip in WHITELIST or ip in IP_BANNED:
        return

    risk = calcular_risco(ip, size)

    event = {
        "ip": ip,
        "size": size,
        "risk": risk,
        "summary": packet.summary(),
        "time": time.time()
    }

    log(f"[EVENT] {ip} | {size}B | RISK {risk:.2f}")

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
                    IP_BANNED.add(ip)
                    log(f"[BAN] {ip}")

            open("feedback_ban.log", "w").close()

        except:
            pass

        time.sleep(2)

# =========================
# DASHBOARD UI
# =========================

@app.route("/")
def index():
    return """
    <html>
    <head>
        <title>SOC V2</title>
        <style>
            body { background:#0d0f14; color:#0f0; font-family:monospace; }
            .high { color:red; }
            .med { color:orange; }
            .low { color:green; }
        </style>
    </head>
    <body>
        <h1>🛡️ SOC V2 - REAL TIME</h1>

        <h2>EVENTOS</h2>
        <ul id="events"></ul>

        <h2>LOGS</h2>
        <ul id="logs"></ul>

        <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
        <script>
            const socket = io();

            socket.on("event", data => {
                let li = document.createElement("li");

                let cls = "low";
                if (data.risk > 0.3) cls = "med";
                if (data.risk > 0.7) cls = "high";

                li.className = cls;
                li.innerHTML = `${data.ip} | ${data.size}B | RISK: ${data.risk.toFixed(2)}`;

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
# SNIF
# =========================

def start_sniffer():
    log("[*] SOC V2 Sentinela rodando...")
    sniff(filter="ip", prn=packet_callback, store=False)

# =========================
# START
# =========================

if __name__ == "__main__":
    threading.Thread(target=feedback_loop, daemon=True).start()
    threading.Thread(target=start_sniffer, daemon=True).start()

    socketio.run(app, host="0.0.0.0", port=5000)
