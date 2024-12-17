from scapy.all import sniff, DNS, DNSQR

# Function to analyze DNS queries
def detect_dns_tunneling(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode()
        if len(domain) > 50:  # Unusually long domain names
            print(f"[ALERT] Potential DNS Tunneling Detected! Domain: {domain}")

# Sniff DNS packets
print("Monitoring DNS traffic for tunneling...")
sniff(filter="udp port 53", prn=detect_dns_tunneling, store=0)
