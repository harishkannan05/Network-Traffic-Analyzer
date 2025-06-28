from scapy.all import IP, TCP, UDP, ICMP, wrpcap
from random import randint

portscan_src = "192.168.1.100" 

# -------------------- Custom Traffic Samples --------------------

# List of packets with different protocols and sources
pkts = [
    IP(src="10.0.0.1", dst="192.37.115.0")/TCP(sport=1234, dport=80),   # Blacklisted DST
    IP(src="217.168.1.2", dst="8.8.8.8")/TCP(sport=4444, dport=443),    # Blacklisted SRC
    IP(src="192.168.1.10", dst="10.0.0.5")/ICMP(),   # ICMP
    IP(src="203.0.113.5", dst="198.51.100.7")/UDP(sport=7777, dport=53) # UDP
]

# Simulating a Port Scan
for port in range(1, 101):
    pkts.append(IP(src=portscan_src, dst="10.0.0.200") / TCP(dport=port))

# Simulating Top Talker (Multiple Interactions)
for i in range(20):
    pkts.append(IP(src="192.168.1.10", dst="192.168.1.9")/TCP(sport=1234, dport=80))

# Save to PCAP File
wrpcap("Sample.pcap", pkts)
print("PCAP file Sample.pcap created", len(pkts), "packets.")
