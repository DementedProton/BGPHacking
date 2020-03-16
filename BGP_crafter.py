from scapy.all import *
from scapy.contrib.bgp import *
from scapy.layers.inet import IP
import hashlib
from TCP_MD5_parser import get_md5_salt_from_bytes, check_password
from scapy.utils import wrpcap
from scapy.compat import raw
import dpkt
from scapy.layers.l2 import Ether
 

def sign_single_packet(packet, password):
    #add an MD5 signature so that the length contains the signature
    packet[TCP].options = [(19,b"\x00"*16)]
    #get bytes
    raw_ip_data = raw(packet[IP])
    raw_tcp_data = raw(packet[TCP])
    #get the salt from these bytes
    salt = get_md5_salt_from_bytes(raw_ip_data, raw_tcp_data)
    #computes the hash
    if type(password)!="bytes":
        password = password.encode("utf-8")
    salt += password
    packet_hash = hashlib.md5(salt).digest()
    #add the signature in the options
    packet[TCP].options = [(19,packet_hash)]

    return packet


def craft_BGP_update(nlri_prefix, path=[], local_pref=0):
    """Returns a scapy BGPupdate packet with the given parameters"""
    header = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)  
    attributes = []
    # 2 bytes or 4 bytes AS numbers ?
    if path != []:
        path_segment = BGPPAAS4Path(segment_value=path, segment_length=len(path), segment_type="AS_SEQUENCE")
        path_attribute = BGPPathAttr(type_flags=0b01000000, type_code=2, attribute=path_segment)
        attributes.append(path_attribute)
    if local_pref != 0:
        pref_attribute = BGPPathAttr(type_flags=0b01000000, type_code=5, attribute=BGPPALocalPref(local_pref=local_pref))
        attributes.append(pref_attribute)
    update = BGPUpdate(path_attr=attributes, nlri=BGPNLRI_IPv4(prefix=nlri_prefix))
    bgp_packet = hdr / update
    return bgp_packet



## EXAMPLE FROM STACK OVERFLOW
src_ipv4_addr = '192.168.12.1'  # eth0
dst_ipv4_addr = '192.168.12.2'
established_port = 36376
expected_seq_num=1000 # ack
current_seq_num=1500 # seq
NLRI_PREFIX = '10.110.99.0/24'

base = IP(src=src_ipv4_addr, dst=dst_ipv4_addr, proto=6, ttl=255)  
tcp = TCP(sport=established_port, dport=179, seq=current_seq_num, ack=expected_seq_num, flags='PA')
up = BGPUpdate(path_attr=[BGPPathAttr(type_flags=64, type_code=5, attribute=BGPPALocalPref(local_pref=100))], nlri=BGPNLRI_IPv4(prefix=NLRI_PREFIX))      
hdr = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)  
# proto=6 represents that, TCP will be travelling above this layer. This is simple IPV4 communication.
# dport=179 means, we are communicating with bgp port of the destination router/ host. sport is a random port over which tcp is established. seq and ack are the sequence number and acknowledgement numbers. flags = PA are the PUSH and ACK flags
# update packet consist of path attributes and NLRI (Network layer reachability information),  type_code in path attributes is for which type of path attribute it is. [more][3]
# type=2 means UPDATE packet will be the BGP Payload, marker field is for authentication. max hex int (all f) are used for no auth.

packet = Ether()/ base / tcp / hdr / up



bgp_packet = craft_BGP_update("192.168.0.1/24", path=[0,1,2,3], local_pref=90)
packet = Ether()/ base / tcp / bgp_packet
packet.show()

packet_list = [packet]
signed_packet = sign_single_packet(packet,"nana")
wrpcap('bgp_crafted.pcap', signed_packet, append=False)