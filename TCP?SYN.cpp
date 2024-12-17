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
