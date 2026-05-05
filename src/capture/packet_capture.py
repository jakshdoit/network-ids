from scapy.all import sniff, get_if_list
from datetime import datetime
import json
import os

# Network interface to capture on
INTERFACE = "en0"

# How many packets to capture (None = capture forever)
PACKET_COUNT = 20

def process_packet(packet):
    """Called automatically for every packet captured."""
    try:
        packet_info = {
            "timestamp": datetime.now().isoformat(),
            "length": len(packet),
            "summary": packet.summary()
        }

        # Extract IP layer info if present
        if packet.haslayer("IP"):
            packet_info["src_ip"]   = packet["IP"].src
            packet_info["dst_ip"]   = packet["IP"].dst
            packet_info["protocol"] = packet["IP"].proto
            packet_info["ttl"]      = packet["IP"].ttl

        # Extract TCP info if present
        if packet.haslayer("TCP"):
            packet_info["src_port"] = packet["TCP"].sport
            packet_info["dst_port"] = packet["TCP"].dport
            packet_info["tcp_flags"]= str(packet["TCP"].flags)

        # Extract UDP info if present
        if packet.haslayer("UDP"):
            packet_info["src_port"] = packet["UDP"].sport
            packet_info["dst_port"] = packet["UDP"].dport

        # Print to terminal
        print(f"[{packet_info['timestamp']}] "
              f"{packet_info.get('src_ip', '?')} -> "
              f"{packet_info.get('dst_ip', '?')} | "
              f"len={packet_info['length']} | "
              f"{packet_info['summary'][:60]}")

        return packet_info

    except Exception as e:
        print(f"[ERROR] Could not process packet: {e}")
        return None


def start_capture(interface=INTERFACE, count=PACKET_COUNT):
    """Start capturing packets on the given interface."""
    print(f"\n🛡️  Network IDS - Packet Capture")
    print(f"📡 Interface : {interface}")
    print(f"📦 Capturing : {count} packets")
    print(f"⏰ Started   : {datetime.now().isoformat()}")
    print("-" * 60)

    captured = []

    def handle_packet(packet):
        info = process_packet(packet)
        if info:
            captured.append(info)

    # Start sniffing
    sniff(iface=interface, prn=handle_packet, count=count, store=False)

    # Save results to raw data folder
    os.makedirs("data/raw", exist_ok=True)
    output_file = f"data/raw/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(output_file, "w") as f:
        json.dump(captured, f, indent=2)

    print("-" * 60)
    print(f"✅ Captured {len(captured)} packets")
    print(f"💾 Saved to {output_file}")
    return captured


if __name__ == "__main__":
    start_capture()
