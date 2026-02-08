from scapy.all import rdpcap, IP, TCP, UDP
from protocols import ENABLED_PLUGINS   

def process_pcap(file_path):
    packets = rdpcap(file_path)
    results = []

    for pkt in packets:
        if pkt.haslayer(IP):
            # Extract Core Networking Info
            entry = {
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "proto": "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other",
                "src_port": pkt.sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else None,
                "dst_port": pkt.dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else None,
                "app_proto": "Unknown",
                "details": ""
            }


            # Check Plugins for Application Layer Protocols
            for plugin in ENABLED_PLUGINS:
                plugin_data = plugin.parse_protocol(pkt)
                if plugin_data:
                    entry["app_proto"] = plugin_data["protocol_name"]
                    entry["details"] = plugin_data["description"]
                    break  # Stop after the first matching plugin

            results.append(entry)

    return results
