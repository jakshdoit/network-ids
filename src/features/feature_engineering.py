import json
import pandas as pd
import numpy as np
import os
from datetime import datetime

# ── Lookup tables ────────────────────────────────────────────
PROTOCOL_MAP = {
    "TCP": 1, "UDP": 2, "ICMP": 3, "ARP": 4,
    "TCP6": 5, "UDP6": 6, "ICMPv6": 7, "UNKNOWN": 0
}

# Ports commonly used in attacks
SUSPICIOUS_PORTS = {
    22, 23, 445, 3389, 4444, 5555, 6666, 7777,
    8080, 8888, 9999, 1337, 31337
}

# Well-known safe service ports
KNOWN_PORTS = {
    80, 443, 53, 123, 67, 68, 25, 110, 143, 993, 995
}

def encode_protocol(proto):
    """Convert protocol string to number."""
    return PROTOCOL_MAP.get(str(proto).upper(), 0)

def encode_tcp_flags(flags):
    """
    Convert TCP flags string to a number 0-255.
    Each bit represents a flag: FIN SYN RST PSH ACK URG
    """
    if not flags:
        return 0
    flag_map = {"F": 1, "S": 2, "R": 4, "P": 8, "A": 16, "U": 32}
    total = 0
    for char in str(flags).upper():
        total += flag_map.get(char, 0)
    return total

def is_suspicious_port(port):
    """Return 1 if port is in suspicious list, else 0."""
    if port is None:
        return 0
    return 1 if int(port) in SUSPICIOUS_PORTS else 0

def is_known_port(port):
    """Return 1 if port is a well-known safe port, else 0."""
    if port is None:
        return 0
    return 1 if int(port) in KNOWN_PORTS else 0

def is_high_port(port):
    """Ports > 1024 are ephemeral/dynamic — return 1 if so."""
    if port is None:
        return 0
    return 1 if int(port) > 1024 else 0

def extract_features(packet):
    """
    Takes one parsed packet dictionary and returns
    a flat dictionary of numeric features for ML.
    """
    src_port = packet.get("src_port") or 0
    dst_port = packet.get("dst_port") or 0
    flags    = packet.get("tcp_flags") or ""

    features = {
        # ── Packet size ──────────────────────────────
        "pkt_length"        : int(packet.get("length", 0)),
        "payload_len"       : int(packet.get("payload_len", 0)),

        # ── Protocol (encoded as int) ─────────────────
        "protocol_enc"      : encode_protocol(packet.get("protocol", "UNKNOWN")),

        # ── Port features ────────────────────────────
        "src_port"          : int(src_port),
        "dst_port"          : int(dst_port),
        "src_port_suspicious": is_suspicious_port(src_port),
        "dst_port_suspicious": is_suspicious_port(dst_port),
        "src_port_known"    : is_known_port(src_port),
        "dst_port_known"    : is_known_port(dst_port),
        "src_port_high"     : is_high_port(src_port),
        "dst_port_high"     : is_high_port(dst_port),

        # ── TCP Flags ────────────────────────────────
        "tcp_flags_enc"     : encode_tcp_flags(flags),
        "has_syn"           : 1 if "S" in str(flags).upper() else 0,
        "has_fin"           : 1 if "F" in str(flags).upper() else 0,
        "has_rst"           : 1 if "R" in str(flags).upper() else 0,
        "has_psh"           : 1 if "P" in str(flags).upper() else 0,
        "has_ack"           : 1 if "A" in str(flags).upper() else 0,

        # ── Address type flags ───────────────────────
        "is_ipv6"           : 1 if packet.get("is_ipv6") else 0,
        "is_arp"            : 1 if packet.get("is_arp") else 0,

        # ── TTL (0 if not present e.g. IPv6/ARP) ─────
        "ttl"               : int(packet.get("ttl") or 0),

        # ── Time of day (hour as 0-23) ───────────────
        "hour_of_day"       : datetime.fromisoformat(
                                packet["timestamp"]).hour
                              if packet.get("timestamp") else 0,
    }
    return features


def engineer_from_file(input_file):
    """Load a parsed JSON file and produce a feature CSV."""
    print(f"\n⚙️  Feature Engineering")
    print(f"📂 Input  : {input_file}")

    with open(input_file) as f:
        packets = json.load(f)

    print(f"📦 Packets: {len(packets)}")

    # Extract features for every packet
    feature_rows = []
    for pkt in packets:
        features = extract_features(pkt)
        # Keep timestamp and raw info alongside features
        features["timestamp"] = pkt.get("timestamp")
        features["src_ip"]    = pkt.get("src_ip")
        features["dst_ip"]    = pkt.get("dst_ip")
        features["protocol"]  = pkt.get("protocol")
        features["summary"]   = pkt.get("summary", "")[:80]
        feature_rows.append(features)

    df = pd.DataFrame(feature_rows)

    # Save to CSV
    os.makedirs("data/processed", exist_ok=True)
    out = f"data/processed/features_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(out, index=False)

    # Print preview
    print("\n📊 Feature Preview (first 3 rows):")
    pd.set_option("display.max_columns", 10)
    pd.set_option("display.width", 100)
    print(df[["protocol", "pkt_length", "protocol_enc",
              "dst_port", "tcp_flags_enc", "has_syn",
              "has_ack", "is_ipv6"]].head(3).to_string())

    print(f"\n📐 Feature shape : {df.shape[0]} rows × {df.shape[1]} columns")
    print(f"✅ Saved to      : {out}")
    return df


if __name__ == "__main__":
    import glob
    files = sorted(glob.glob("data/processed/parsed_*.json"))
    if not files:
        print("❌ No parsed JSON files found in data/processed/")
        print("   Run the parser first!")
    else:
        latest = files[-1]
        print(f"📄 Using latest file: {latest}")
        engineer_from_file(latest)
