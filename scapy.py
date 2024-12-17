from scapy.all import ARP, sniff

# Dictionary to store IP-MAC pairs
ip_mac_map = {}

# Function to detect ARP spoofing
def detect_arp_spoof(packet):
    if packet.haslayer(ARP):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        # Check if IP already exists with a different MAC
        if ip in ip_mac_map and ip_mac_map[ip] != mac:
            print(f"[ALERT] ARP Spoofing Detected! IP: {ip} is now mapped to MAC: {mac}")
        else:
            ip_mac_map[ip] = mac

# Sniff ARP packets
print("Monitoring ARP packets for spoofing...")
sniff(filter="arp", prn=detect_arp_spoof, store=0)
