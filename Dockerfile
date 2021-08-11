FROM ubuntu:18.04
RUN apt-get update
RUN apt-get -y install curl nano openjdk-11-jdk python3 python3-pip build-essential libpcap-dev golang-go libtins-dev 
RUN apt-get -y install wget && \ 
    DEBIAN_FRONTEND=noninteractive apt-get -y install hping3 && \
    apt-get clean
RUN pip3 install libpcap dpkt pcapy pypcap scapy
RUN apt-get -y install vim net-tools
RUN apt-get -y install tcpdump iptables
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install wireshark
#ENTRYPOINT ["hping3"] 
WORKDIR "/tmp"

