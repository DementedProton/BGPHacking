import sys, os
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from scapy.contrib.bgp import *
import struct
from scapy.compat import raw


def IP_to_hexstring(s):
    h = ""
    #remove dots
    l = s.split(".")
    for i in l:
        h += "{:02x}".format(int(i))
    return h 


def get_hashed_message(p):
    """
    Returns a hex string with the contents hashed in the TCP md5 option (except the password):
        md5(get_hashed_message(p) + password) = tcp md5 checksum
    """
    message = ""
    # TCP pseudo header
    message += IP_to_hexstring(p[IP].src)
    message += IP_to_hexstring(p[IP].dst)
    message += "{:02x}".format(p[IP].proto)
    message += "{:04x}".format(p[IP].len)
    #TCP header, excluding options and with checksum = 0
    header = raw(p[TCP])
    s = header[:16] + b"\x00\x00" + header[18:20]
    s = s.hex()
    message += s
    #TCP segment data (payload)
    s = raw(p[TCP].payload).hex()
    #if no payload, s = ""
    message += s
    return message

def parse_packets(packets):
    hash_pairs = []
    for p in packets:
        if TCP in p:
            if p[TCP].sport == 179 or p[TCP].dport == 179:
                #if it is a BGP packet
                options_types = [o[0] for o in p[TCP].options]
                if 19 in options_types:
                    md5_hash = (p[TCP].options[options_types.index(19)][1]).hex()
                    message = get_hashed_message(p)
                    hash_pairs.append((md5_hash, message))
    return hash_pairs



def hashcat_command(md5_hash, message, bytes_mask=6):
    #Add --increment for increment of length
    c = "hashcat -m 0 -a 3 --hex-charset "  + md5_hash + " " + message + "?h" * bytes_mask
    return c
if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = "BGP_MD5.cap"
        # input_file = input("Input file (pcap): ")
    
    packets = scapy.rdpcap(input_file)
    hash_pairs = parse_packets(packets)
    for p in hash_pairs:
        h,m = p[0], p[1]
        print(h + " " + m)
        # print(hashcat_command(h,m,bytes_mask=7))
