import sys
import os
import threading
import time
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
from src.alerts.alert_logger import get_recent_alerts

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Shared state ──────────────────────────────────────────────────────────────
sniffer_thread  = None
sniffer_running = False
stats = {
    "total"    : 0,
    "normal"   : 0,
    "anomalies": 0,
    "started_at": None,
}

# ── Packet handler (runs in sniffer thread) ───────────────────────────────────
def _packet_handler(packet):
    from src.detection.detector import detect
    from src.alerts.alert_logger import log_detection, raise_alert

    result = detect(packet)
    if result is None:
        return

    log_detection(result)
    raise_alert(result)

    # Update stats
    stats["total"] += 1
    if result["label"] == "ANOMALY":
        stats["anomalies"] += 1
    else:
        stats["normal"] += 1

    # Emit to all connected dashboard clients in real time
    socketio.emit("detection", {
        "timestamp" : datetime.now().isoformat(),
        "label"     : result["label"],
        "score"     : result["score"],
        "src_ip"    : result["src_ip"],
        "dst_ip"    : result["dst_ip"],
        "src_port"  : result["src_port"],
        "dst_port"  : result["dst_port"],
        "protocol"  : result["protocol"],
        "pkt_len"   : result["pkt_len"],
    })

# ── Sniffer loop ──────────────────────────────────────────────────────────────
def _sniffer_loop():
    from scapy.all import sniff
    global sniffer_running
    print("[+] Sniffer thread started on en0")
    while sniffer_running:
        sniff(iface="en0", prn=_packet_handler, count=10, store=False, timeout=5)
    print("[+] Sniffer thread stopped")

# ── API Routes ────────────────────────────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def status():
    return jsonify({
        "running"   : sniffer_running,
        "stats"     : stats,
        "uptime"    : str(datetime.now() - datetime.fromisoformat(stats["started_at"]))
                      if stats["started_at"] else "0:00:00",
    })

@app.route("/api/start", methods=["POST"])
def start_sniffer():
    global sniffer_thread, sniffer_running
    if sniffer_running:
        return jsonify({"message": "Sniffer already running"}), 200

    sniffer_running      = True
    stats["started_at"]  = datetime.now().isoformat()
    stats["total"]       = 0
    stats["normal"]      = 0
    stats["anomalies"]   = 0

    sniffer_thread = threading.Thread(target=_sniffer_loop, daemon=True)
    sniffer_thread.start()
    return jsonify({"message": "Sniffer started"}), 200

@app.route("/api/stop", methods=["POST"])
def stop_sniffer():
    global sniffer_running
    sniffer_running = False
    return jsonify({"message": "Sniffer stopped"}), 200

@app.route("/api/alerts", methods=["GET"])
def alerts():
    return jsonify(get_recent_alerts(limit=50))

@app.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify(stats)

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[+] Starting Network IDS API on http://localhost:5001")
    socketio.run(app, host="0.0.0.0", port=5001, debug=False, use_reloader=False)
