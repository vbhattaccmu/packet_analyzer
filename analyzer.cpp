#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

class PacketAnalyzer {
public:
    PacketAnalyzer() : handle(nullptr) {}

    ~PacketAnalyzer() {
        if (handle != nullptr) {
            pcap_close(handle);
        }
    }

    bool initialize() {
        char errorBuffer[PCAP_ERRBUF_SIZE];
        const char *dev;

        dev = pcap_lookupdev(errorBuffer); // Get the default network device
        if (dev == nullptr) {
            std::cout << "Failed to find default network device: " << errorBuffer << std::endl;
            return false;
        }

        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errorBuffer); // Open the network device for live capture
        if (handle == nullptr) {
            std::cout << "Failed to open device " << dev << ": " << errorBuffer << std::endl;
            return false;
        }

        return true;
    }

    void startCapture() {
        pcap_loop(handle, -1, packetHandler, nullptr); // Start capturing packets and pass them to the packetHandler function
    }

private:
    static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packetData) {
        struct ip *ipHeader;
        struct tcphdr *tcpHeader;
        int ipHeaderSize;

        ipHeader = (struct ip *)(packetData + 14); // Skip Ethernet header (14 bytes)
        ipHeaderSize = ipHeader->ip_hl * 4; // Get IP header size in bytes

        if (ipHeader->ip_p == IPPROTO_TCP) { // Process only TCP packets
            tcpHeader = (struct tcphdr *)(packetData + 14 + ipHeaderSize); // Skip Ethernet and IP headers
            std::cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
            std::cout << "Destination IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
            std::cout << "Source Port: " << ntohs(tcpHeader->th_sport) << std::endl;
            std::cout << "Destination Port: " << ntohs(tcpHeader->th_dport) << std::endl;
            std::cout << "------------------------------" << std::endl;
        }
    }

private:
    pcap_t *handle;
};

int main() {
    PacketAnalyzer analyzer;

    if (analyzer.initialize()) {
        analyzer.startCapture();
    }

    return 0;
}
