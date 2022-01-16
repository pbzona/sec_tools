from scapy.all import sniff
IP_MAC_Map = {}

def process_packet(packet):
    src_IP = packet['ARP'].psrc
    src_MAC = packet['Ether'].src
    if src_MAC in IP_MAC_Map.keys():
        try:
            old_IP = IP_MAC_Map[src_MAC]
        except:
            old_IP = "unknown"
        message = ("\nPossible ARP spoofing attack detected\n"
            + f"It's possible the machine with IP address {old_IP} is pretending to be {src_IP}\n"
            )
        return message
    else:
        IP_MAC_Map[src_MAC] = src_IP

sniff(count=0, filter="arp", store=0, prn=process_packet)