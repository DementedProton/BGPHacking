import sys, os
import dpkt
import hashlib

def parse_packets_md5(file):
    """ 
        parse the pcap file looking for TCP MD5 signatures. 
        This function is mostly inspired by the tool pcap2john: https://github.com/truongkma/ctf-tools/blob/master/John/run/pcap2john.py
    """
    hashes = []                      
    with open(input_file,'rb') as f:
        capture = dpkt.pcap.Reader(f)
        for _, buf in capture:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                #if it is not an IP packet, skip it
                continue
            ip = eth.data
            if ip.v != 4 or ip.p != dpkt.ip.IP_PROTO_TCP:
                #if it is not an IPv4 TCP packet
                continue
            tcp = ip.data
            if tcp.off * 4 >= 40 and len(tcp.opts) > 18:
                # if the TCP packet has an option which is more than 18 bytes long
                raw_ip_data = ip.pack()
                raw_tcp_data = tcp.pack()
                length = len(raw_tcp_data)
                for opt_type, opt_data in dpkt.tcp.parse_opts(tcp.opts):
                    # skip over "undesired" option fields
                    # TCP_OPT_MD5 = 19 implies TCP MD5 signature, RFC 2385
                    if opt_type == 19:
                        found = True
                        break
                if found and opt_type == 19 and len(opt_data) == 16:
                    #if the MD5 option has been found, the other conditions are additional checks
                    #opt_data contains the option
                    header_length = tcp.off * 4
                    data_length = length - header_length
                    # print length, header_length, data_length
                    # TCP pseudo-header + TCP header + TCP segment data
                    # salt_length = 12 + 20 + data_length
                    # add TCP pseudo-header
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
                    hashes.append((opt_data, salt))
    return hashes

def write_hashes_to_file(hashes,output_file):
    with open(output_file,'w') as out:
        for h,salt in hashes:
            out.write("{}:{}\n".format(h.hex(), salt.hex()))

def check_password(packet_hash, salt, password):
    print("{:<16} | {:<32} | {:<32} | {:<64}".format("Password","Packet Hash", "Computed Hash", "Salt (first 64 bytes)"))
    if type(password)!="bytes":
        password = password.encode("utf-8")
    salt += password
    h = hashlib.md5(salt).hexdigest()
    sys.stdout.write("{:<16} | {} | {} | {}\n".format(password.decode("utf-8"),packet_hash.hex(), h, salt.hex()[:64])) 

def launch_hashcat(h,s,mask):
    s_hash = h.hex() + ":" + s.hex()
    c = "hashcat-5.1.0/hashcat64.bin -m 20 -a 3 --hex-salt {} {}".format(s_hash, mask)
    os.system(c)
    os.system(c + " --show")


if __name__ == "__main__":
    input_file = "bgp_simulation.pcap"
    hashes = parse_packets_md5(input_file)
    # password = "test"
    # check_password(hashes[0][0],hashes[0][1],password)
    mask = "-1 ?u?l -2 ?u?l?d ?2?2?2?2?2?2 --increment --increment-min 4"
    launch_hashcat(hashes[0][0], hashes[0][1], mask)