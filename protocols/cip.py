# protocols/cip.py

class CIPDecoder:
    def __init__(self):
        self.protocol_name = "CIP (EtherNet/IP)"
        self.standard_port = 44818  # Default port for CIP over TCP

    def decode(self, packet):
        """
        Extracts basic CIP/EtherNet/IP fields if the packet matches.
        """
        # Check if the packet has a TCP layer and matches the CIP port
        if packet.haslayer("TCP") and (packet["TCP"].dport == self.standard_port or packet["TCP"].sport == self.standard_port):
            payload = bytes(packet["TCP"].payload)
            
            if len(payload) >= 2:
                # CIP Encapsulation Header: Command is the first 2 bytes
                command_code = payload[0:2].hex()
                return {
                    "Protocol": self.protocol_name,
                    "Command Code": f"0x{command_code}",
                    "Status": "Detected"
                }
        return None