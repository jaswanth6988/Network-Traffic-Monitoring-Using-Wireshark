1. Setting Up Wireshark for Packet Capturing
Steps:

Install Wireshark: Download and install Wireshark from wireshark.org.
Capture Traffic: Open Wireshark and select the network interface to monitor. Start capturing packets.
Filter Packets: Apply filters like arp, dns, and tcp.flags.syn==1 to focus on ARP spoofing, DNS requests, and unauthorized access attempts.
Wireshark Filters:

ARP Spoofing:
Copy code
arp.opcode == 2
Unauthorized Access (TCP SYN floods):
Copy code
tcp.flags.syn == 1
DNS Tunneling:
Copy code
dns.qry.name
2. Detecting ARP Spoofing Using Python
Explanation:
ARP spoofing involves sending fake ARP packets to associate a malicious MAC address with a legitimate IP address. Python can analyze ARP packets captured using libraries like Scapy.

Code:

python
Copy code
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
How to Run:

Save the code in a file, e.g., arp_spoof_detector.py.
Run with sudo python3 arp_spoof_detector.py (requires root permission).
3. Detecting Unauthorized Access Attempts Using C++
Explanation:
By monitoring TCP SYN packets, unauthorized access attempts can be detected (e.g., port scanning).

Code:

cpp
Copy code
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

// Callback function for processing packets
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *iph = (struct ip *)(packet + 14);  // Skipping Ethernet header
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4);
        if (tcph->syn && !tcph->ack) {
            cout << "[ALERT] TCP SYN packet detected! Source IP: " 
                 << inet_ntoa(iph->ip_src) << ", Destination Port: " << ntohs(tcph->dest) << endl;
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open live network interface for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Error: " << errbuf << endl;
        return 1;
    }

    cout << "Monitoring for unauthorized access attempts..." << endl;
    pcap_loop(handle, 0, process_packet, nullptr);

    pcap_close(handle);
    return 0;
}
How to Compile and Run:

Install libpcap (Linux): sudo apt-get install libpcap-dev
Save the code in unauthorized_access.cpp.
Compile:
Copy code
g++ unauthorized_access.cpp -o unauthorized_access -lpcap
Run:
bash
Copy code
sudo ./unauthorized_access
4. Detecting DNS Tunneling Using Python
Explanation:
DNS tunneling embeds data in DNS queries. We look for unusually long domain names or excessive DNS queries from a single source.

Code:

python
Copy code
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
How to Run:

Save the code as dns_tunneling_detector.py.
Run with:
Copy code
sudo python3 dns_tunneling_detector.py
5. Integrating Wireshark with Automated Analysis
After capturing traffic with Wireshark:

Save Captures: Save packets as a .pcap file.
Use Scripts for Analysis:
Analyze ARP packets using the Python ARP spoofing script.
Detect DNS tunneling by processing DNS packets.
Identify unauthorized access using the C++ program.
Example: Loading a .pcap file in Python:

python
Copy code
from scapy.all import rdpcap

packets = rdpcap("capture.pcap")  # Load Wireshark capture
for packet in packets:
    if packet.haslayer(DNS):
        print(packet.summary())
Workflow Summary
Capture Traffic using Wireshark.
Live Monitoring:
ARP spoofing detection using Python.
Unauthorized access detection using C++.
DNS tunneling detection using Python.
Automated Analysis:
Process .pcap files for deeper inspection.
