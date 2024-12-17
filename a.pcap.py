from scapy.all import rdpcap

packets = rdpcap("capture.pcap")  # Load Wireshark capture
for packet in packets:
    if packet.haslayer(DNS):
        print(packet.summary())
