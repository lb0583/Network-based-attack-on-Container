from scapy.all import *

# Path to the pcap file to save captured network traffic
pcap_file = 'syn_packets.pcap'

def capture_syn_packets(packet):
    # Check if the packet is a TCP packet with SYN flag set
    if TCP in packet and packet[TCP].flags & 2 != 0:
        # Write the packet to the pcap file
        wrpcap(pcap_file, packet, append=True)

# Sniff network traffic and call capture_syn_packets function for each packet
sniff(prn=capture_syn_packets, store=0)
