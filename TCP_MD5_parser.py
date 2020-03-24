import sys, os
import dpkt
import hashlib
import time


def get_md5_salt_from_bytes(raw_ip_data, raw_tcp_data):
    """Parse the packet bytes to get the signature
    
    Args:
        raw_ip_data (bytes): bytes of the IP packet
        raw_tcp_data (bytes): bytes of the TCP packet
    Returns:
        bytes: salt for the TCP MD5 signature
    """
    # TCP pseudo-header + TCP header + TCP segment data
    # add TCP pseudo-header
    tcp = dpkt.tcp.TCP()
    tcp.unpack(raw_tcp_data)
    length = len(raw_tcp_data)
    header_length = tcp.off * 4
    data_length = length - header_length
    salt = raw_ip_data[12:12 + 8]  # src. and dest. IP
    salt = salt + b"\x00"  # zero padding
    salt = salt + raw_ip_data[9].to_bytes(1,"little")  # protocol
    salt = salt + (length // 256).to_bytes(1,"little")  # segment length
    salt = salt + (length % 256).to_bytes(1,"little")  # segment length
    # add TCP header
    salt = salt + raw_tcp_data[:16]  # TCP header without checksum
    salt = salt + (b"\x00" * 4)  # add zero checksum
    # add segment data
    salt = salt + raw_tcp_data[header_length:header_length + data_length]
    return salt

def get_md5_salt(buf):
    """Gets the TCP pseudo-header + TCP header + TCP segment data of a TCP packet. 
    This form the salt of the MD5 signature of the packet
    This function gets bytes from the dpkt packet and calls get_md5_salt_from_bytes()
    
    Args:
        buf (dpkt buffer): The packet gotten from a dpkt reader object. The packet must have an Ethernet, IP and TCP layer
    
    Returns:
        (bytes): The salt of the MD5
    """
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    raw_ip_data = ip.pack()
    raw_tcp_data = tcp.pack()
    salt = get_md5_salt_from_bytes(raw_ip_data, raw_tcp_data)
    return salt

def get_md5_signature(buf):
    """Parses a packet to find a TCP MD5 signature.
    
    Args:
        buf (bytes): The packet as bytes. The packet must have an Ethernet, IP and TCP layer
    
    Returns:
        (bytes): The signature of the MD5. If no signatures were found, returns None
    """
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    md5_found = False
    for opt_type, opt_data in dpkt.tcp.parse_opts(tcp.opts):
        # skip over "undesired" option fields
        # TCP_OPT_MD5 = 19 implies TCP MD5 signature, RFC 2385
        if opt_type == 19:
            md5_found = True
            return opt_data
    if md5_found == False:
        # If no MD5 found return None
        print("No MD5 signature found in the packet")
        return None


def check_if_TCP(buf):
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        #if it is not an IP packet, skip it
        return False
    ip = eth.data
    if ip.v != 4 or ip.p != dpkt.ip.IP_PROTO_TCP:
        #if it is not an IPv4 TCP packet
        return False
    return True

def parse_signed_packets_md5(file):
    """Parse a pcap file, looking for TCP MD5 signed packets and returning a list of tuples (hash, salt)
    
    Args:
        file (string): A pcap file name
    
    Returns:
        list: A list of tuples (hash, salt)
    """
    # This function is mostly inspired by the tool pcap2john: https://github.com/truongkma/ctf-tools/blob/master/John/run/pcap2john.py
    hashes = []         
    with open(input_file,'rb') as f:
        capture = dpkt.pcap.Reader(f)
        for _, buf in capture:
            if check_if_TCP(buf):
                packet_md5 = get_md5_signature(buf)
                salt = get_md5_salt(buf)
                hashes.append((packet_md5, salt))
    return hashes

def check_password(packet_hash, salt, password):
    if packet_hash is None:
        packet_hash = ""
    print("{:<16} | {:<32} | {:<32} | {:<64}".format("Password","Packet Hash", "Computed Hash", "Salt (first 64 bytes)"))
    if type(password)!="bytes":
        password = password.encode("utf-8")
    salt += password
    h = hashlib.md5(salt).hexdigest()
    sys.stdout.write("{:<16} | {} | {} | {}\n".format(password.decode("utf-8"),packet_hash.hex(), h, salt.hex()[:64])) 

def launch_hashcat(h,s,mask):
    """Launch hashcat to launch a mask attack using the givan mask on a MD5 hash with the given salt
    
    Args:
        h (bytes): the hash in bytes
        s (bytes): the salt in bytes
        mask (string): the mask to use (can also contain hashcat options)
    """
    s_hash = h.hex() + ":" + s.hex()
    c = "hashcat-5.1.0/hashcat64.bin -m 20 -a 3 --hex-salt {} {}".format(s_hash, mask)
    os.system(c + " > /dev/null 2> /dev/null")
    #risk of command injection if letting user input there
    result = os.popen(c + " --show").read()
    return result


if __name__ == "__main__":
    input_file = "captures/bgp_crafted.pcap"
    hashes = parse_signed_packets_md5(input_file)
    check_password(hashes[0][0], hashes[0][1], "nana")
    mask = "-1 ?u?l -2 ?u?l?d ?1?1?1?1?1?1 --increment --increment-min 4"
    launch_hashcat(hashes[0][0], hashes[0][1], mask)