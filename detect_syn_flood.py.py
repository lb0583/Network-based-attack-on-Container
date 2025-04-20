from scapy.all import *
import subprocess

pcap_file='syn_packets.pcap'

syn_threshold = 100

def block_ip_address(ip_address):
    # Add a rule to block incoming traffic from the specified IP address using iptables
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
    print(f"Blocked incoming traffic from {ip_address}")

def detect_syn_flood(pcap_file, syn_threshold):
    syn_count = 0
    
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Iterate over each packet in the pcap file
    for packet in packets:
        # Check if the packet is a TCP packet with SYN flag set
        if TCP in packet and packet[TCP].flags & 2 != 0:
            syn_count += 1
            # If SYN count exceeds threshold, block IP address
            if syn_count > syn_threshold:
                attacker_ip = packet[IP].src
                block_ip_address(attacker_ip)
                print(f"SYN flood attack detected! SYN count: {syn_count}, Blocking IP: {attacker_ip}")
                # Implement other response mechanisms here
                return

    # If no SYN flood attack detected
    print("No SYN flood attack detected. SYN count:", syn_count)

# Call the function to detect SYN flood attack
detect_syn_flood(pcap_file, syn_threshold)
