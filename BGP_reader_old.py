import sys, os
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from scapy.contrib.bgp import *
from scapy.compat import raw
import hashlib
import struct
import binascii
from socket import inet_aton
import dpkt


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
    # Padd protocol to 2 bytes
    message += "00"
    message += "{:02x}".format(p[IP].proto)
    message += "{:04x}".format(p[IP].len)
    # struct_message = struct.pack("!4s4sHH", inet_aton(p[IP].src), inet_aton(p[IP].dst), p[IP].proto, p[IP].len)
    # at this point message == struc_message
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


def test_hashcat(password, message):
    """Test hashcat breaking with a chosen password"""
    file_hash = "hast_test.txt"
    s = bytes.fromhex(message) + bytes(password, encoding='utf-8')
    h = hashlib.md5(s).hexdigest()
    with open("hash_test", "w") as f:
        f.write(h + ':' + message)
    os.system("hashcat-5.1.0/hashcat64.bin -m 20 -a 3 --hex-salt {} ?u?l?l?l?l".format(file_hash))
    os.remove(file_hash)


def hashcat_crack(md5_hash, message, mask, increment=False, increment_b=(1,9)):
    file_hash = "hast_test.txt"
    s = bytes.fromhex(message)
    with open(file_hash, "w") as f:
        f.write(md5_hash + ':' + message)
    c = "hashcat-5.1.0/hashcat64.bin -m 20 -a 3 --hex-salt {} {}".format(file_hash, mask)
    if increment:
        c += " --increment --increment-min {} --increment-max {}".format(increment_b[0], increment_b[1])
    os.system(c)
    os.system(c + " --show")
    os.remove(file_hash)


def compare_hashes(packet_hash, message, password):
    s = bytes.fromhex(message) + bytes(password, encoding="utf-8")
    computed_hash = hashlib.md5(s).hexdigest()
    print("\n{0:<10}".format("Computed:"), computed_hash)
    print("{0:<10}".format("Packet:"), packet_hash)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = "bgp_packets.pcap"
    
    packets = scapy.rdpcap(input_file)
    hash_pairs = parse_packets(packets)
    for p in hash_pairs:
        h,m = p[0], p[1]
        compare_hashes(h, m, "test")

    #try to break the BGP password
    # mask = "-1 ?u?l -2 ?u?l?d ?2?2?2?2"
    # hashcat_crack(h,m,mask, increment=False)