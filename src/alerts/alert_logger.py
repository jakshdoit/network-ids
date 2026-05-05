import json
import os
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
ALERT_DIR      = "data/alerts"
ALERT_FILE     = os.path.join(ALERT_DIR, "alerts.json")
LOG_FILE       = os.path.join(ALERT_DIR, "detections.log")
COOLDOWN_SECS  = 10   # min seconds between alerts for the same src_ip

os.makedirs(ALERT_DIR, exist_ok=True)

# tracks last alert time per src_ip
_last_alert_time = {}

# ── Load existing alerts ──────────────────────────────────────────────────────
def _load_alerts():
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

# ── Save alerts ───────────────────────────────────────────────────────────────
def _save_alerts(alerts):
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

# ── Log every detection (normal + anomaly) ────────────────────────────────────
def log_detection(result):
    """Append one detection result to the flat log file."""
    if result is None:
        return

    timestamp = datetime.now().isoformat()
    line = (
        f"[{timestamp}] {result['label']} | score={result['score']:+.4f} | "
        f"{result['src_ip']}:{result['src_port']} → "
        f"{result['dst_ip']}:{result['dst_port']} | "
        f"{result['protocol']} | {result['pkt_len']}B\n"
    )
    with open(LOG_FILE, "a") as f:
        f.write(line)

# ── Raise an alert only for anomalies (with cooldown) ────────────────────────
def raise_alert(result):
    """
    If the result is an ANOMALY and cooldown has passed for this src_ip,
    save it to alerts.json and print a loud warning.
    """
    if result is None or result["label"] != "ANOMALY":
        return

    src_ip = result["src_ip"]
    now    = datetime.now().timestamp()

    # Cooldown check
    if src_ip in _last_alert_time:
        elapsed = now - _last_alert_time[src_ip]
        if elapsed < COOLDOWN_SECS:
            return  # too soon, skip

    _last_alert_time[src_ip] = now

    # Build alert record
    alert = {
        "timestamp" : datetime.now().isoformat(),
        "src_ip"    : src_ip,
        "dst_ip"    : result["dst_ip"],
        "src_port"  : result["src_port"],
        "dst_port"  : result["dst_port"],
        "protocol"  : result["protocol"],
        "pkt_len"   : result["pkt_len"],
        "score"     : result["score"],
        "summary"   : result.get("summary", ""),
    }

    # Append to JSON store
    alerts = _load_alerts()
    alerts.append(alert)
    _save_alerts(alerts)

    # Print loud warning
    print(f"\n🚨 ALERT! Anomalous traffic from {src_ip}")
    print(f"   → {result['dst_ip']}:{result['dst_port']} | "
          f"score={result['score']:+.4f} | {result['protocol']}")
    print(f"   Saved to {ALERT_FILE}\n")

# ── Retrieve recent alerts (for dashboard) ───────────────────────────────────
def get_recent_alerts(limit=50):
    """Return the last `limit` alerts from alerts.json."""
    alerts = _load_alerts()
    return alerts[-limit:]

