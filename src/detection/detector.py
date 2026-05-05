import pickle
import pandas as pd
import numpy as np
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.parser.packet_parser import parse_packet
from src.features.feature_engineering import extract_features

MODEL_DIR = "models"

with open(f"{MODEL_DIR}/isolation_forest.pkl", "rb") as f:
    model = pickle.load(f)

with open(f"{MODEL_DIR}/scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

with open(f"{MODEL_DIR}/feature_list.pkl", "rb") as f:
    feature_list = pickle.load(f)

print(f"[+] Model loaded — {len(feature_list)} features expected")

def detect(packet):
    try:
        parsed = parse_packet(packet)
        if parsed is None:
            return None

        features = extract_features(parsed)
        if features is None:
            return None

        row = {col: features.get(col, 0) for col in feature_list}
        df_row = pd.DataFrame([row])[feature_list]

        X_scaled = scaler.transform(df_row)
        score = model.decision_function(X_scaled)[0]
        pred  = model.predict(X_scaled)[0]
        label = "ANOMALY" if pred == -1 else "NORMAL"

        return {
            "label"    : label,
            "score"    : round(float(score), 4),
            "src_ip"   : parsed.get("src_ip", "?"),
            "dst_ip"   : parsed.get("dst_ip", "?"),
            "protocol" : parsed.get("protocol", "?"),
            "src_port" : parsed.get("src_port"),
            "dst_port" : parsed.get("dst_port"),
            "pkt_len"  : parsed.get("pkt_length", 0),
            "summary"  : parsed.get("summary", ""),
        }

    except Exception as e:
        print(f"[!] Detection error: {e}")
        return None


def _fmt_addr(ip, port):
    """Format ip:port cleanly — omit port if None."""
    if port is not None:
        return f"{ip}:{port}"
    return str(ip)


def print_result(result):
    if result is None:
        return
    icon = "⚠️  ANOMALY" if result["label"] == "ANOMALY" else "✅ NORMAL "
    src  = _fmt_addr(result["src_ip"], result["src_port"])
    dst  = _fmt_addr(result["dst_ip"], result["dst_port"])
    print(f"{icon} | score={result['score']:+.4f} | {src} → {dst} | {result['protocol']} | {result['pkt_len']}B")


def detect_and_alert(packet):
    """Full pipeline: detect + log + alert. Returns None to suppress Scapy output."""
    from src.alerts.alert_logger import log_detection, raise_alert
    result = detect(packet)
    if result:
        log_detection(result)
        raise_alert(result)
        print_result(result)
    return None   # ← prevents Scapy from printing the dict
