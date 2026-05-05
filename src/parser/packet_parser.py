from scapy.all import sniff, ARP, IP, IPv6, TCP, UDP, ICMP, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
from datetime import datetime
import json
import os

def parse_packet(packet):
    """
    Takes a raw Scapy packet and returns a clean structured dictionary.
    Handles IPv4, IPv6, TCP, UDP, ICMP, and ARP packets.
    """
    parsed = {
        "timestamp"  : datetime.now().isoformat(),
        "length"     : len(packet),
        "protocol"   : "UNKNOWN",
        "src_ip"     : None,
        "dst_ip"     : None,
        "src_port"   : None,
        "dst_port"   : None,
        "ttl"        : None,
        "tcp_flags"  : None,
        "is_ipv6"    : False,
        "is_arp"     : False,
        "payload_len": 0,
        "summary"    : packet.summary()
    }

    # ── ARP packets ──────────────────────────────────────────
    if packet.haslayer(ARP):
        arp = packet[ARP]
        parsed["protocol"] = "ARP"
        parsed["src_ip"]   = arp.psrc   # sender IP
        parsed["dst_ip"]   = arp.pdst   # target IP
        parsed["is_arp"]   = True

    # ── IPv4 packets ─────────────────────────────────────────
    elif packet.haslayer(IP):
        ip = packet[IP]
        parsed["src_ip"]   = ip.src
        parsed["dst_ip"]   = ip.dst
        parsed["ttl"]      = ip.ttl

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            parsed["protocol"]  = "TCP"
            parsed["src_port"]  = tcp.sport
            parsed["dst_port"]  = tcp.dport
            parsed["tcp_flags"] = str(tcp.flags)
            parsed["payload_len"] = len(tcp.payload)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            parsed["protocol"]  = "UDP"
            parsed["src_port"]  = udp.sport
            parsed["dst_port"]  = udp.dport
            parsed["payload_len"] = len(udp.payload)

        elif packet.haslayer(ICMP):
            parsed["protocol"] = "ICMP"
            parsed["payload_len"] = len(ip.payload)

        else:
            parsed["protocol"] = f"IPv4-OTHER({ip.proto})"

    # ── IPv6 packets ─────────────────────────────────────────
    elif packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        parsed["src_ip"]  = ipv6.src
        parsed["dst_ip"]  = ipv6.dst
        parsed["is_ipv6"] = True

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            parsed["protocol"]  = "TCP6"
            parsed["src_port"]  = tcp.sport
            parsed["dst_port"]  = tcp.dport
            parsed["tcp_flags"] = str(tcp.flags)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            parsed["protocol"]  = "UDP6"
            parsed["src_port"]  = udp.sport
            parsed["dst_port"]  = udp.dport

        else:
            parsed["protocol"] = "ICMPv6"

    return parsed


def print_parsed(p):
    """Pretty-print a parsed packet to the terminal."""
    proto = p["protocol"].ljust(10)
    src   = f"{p['src_ip'] or '?'}:{p['src_port'] or '-'}"
    dst   = f"{p['dst_ip'] or '?'}:{p['dst_port'] or '-'}"
    flags = f"[{p['tcp_flags']}]" if p["tcp_flags"] else ""
    print(f"  {proto} | {src:<35} -> {dst:<35} | len={p['length']} {flags}")


def parse_live(interface="en0", count=20):
    """Capture and parse live packets."""
    print(f"\n🔍 Packet Parser - Live Mode")
    print(f"📡 Interface : {interface}")
    print(f"📦 Parsing   : {count} packets")
    print("-" * 90)

    results = []

    def handle(packet):
        p = parse_packet(packet)
        print_parsed(p)
        results.append(p)

    sniff(iface=interface, prn=handle, count=count, store=False)

    # Save parsed output
    os.makedirs("data/processed", exist_ok=True)
    out = f"data/processed/parsed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)

    # Summary stats
    print("-" * 90)
    protocols = {}
    for p in results:
        protocols[p["protocol"]] = protocols.get(p["protocol"], 0) + 1

    print(f"\n📊 Protocol Breakdown:")
    for proto, count_ in sorted(protocols.items(), key=lambda x: -x[1]):
        print(f"   {proto:<15} : {count_} packets")

    print(f"\n✅ Parsed {len(results)} packets")
    print(f"💾 Saved to {out}")
    return results


if __name__ == "__main__":
    parse_live()
