from scapy.all import TCP, IP, Raw

def parse_protocol(packet):
    """
    Analyzes a pakcte to see if it is Modbus TCP.
    Returns a dictionary of data or None if not mOdbus
    """

    #Check if the packet has a TCP layer and uses port 502 (default Modbus)
    if packet.haslayer(TCP) and (packet[TCP].sport == 502 or packet[TCP].dport == 502):

        #Get the raw data after the TCP header
        payload = bytes(packet[TCP].payload)

        # Basic Modbus TCP Header (MBAP) is 7 bytes
        if len(payload) >= 7:
            # MBAP header: Transaction ID (2 bytes), Protocol ID (2 bytes), Length (2 bytes), Unit ID (1 byte)
            unit_id = payload[6]

            # The function code is the 8th byte (index = 7)
            function_code = payload[7] if len(payload) > 7 else "Unknown"

            return {        
                "protocol_name": "Modbus TCP",
                "unit_id": unit_id,
                "function_code": function_code,
                "description": f"Unit: {unit_id}, Func: {function_code}"     
            }
            
            return None