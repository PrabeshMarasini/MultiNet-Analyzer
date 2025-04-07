#include <pcap.h>
#include <stdio.h>
#include <winsock2.h>
#include <stdint.h>
#include <stdlib.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

// Ethernet header
struct ethhdr {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};

// IP header
struct iphdr {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

// Convert IP to string
char *ip_to_str(uint32_t ip, char *buf) {
    unsigned char *p = (unsigned char *)&ip;
    sprintf(buf, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return buf;
}

// Print MAC
void print_mac(const uint8_t *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct ethhdr *eth = (struct ethhdr *)pkt_data;

    printf("\n[+] Ethernet Frame:\n");
    printf("    Src MAC: ");
    print_mac(eth->src);
    printf(" → Dst MAC: ");
    print_mac(eth->dest);
    printf("\n");

    if (ntohs(eth->type) == 0x0800) { // IP Packet
        struct iphdr *ip = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
        char src_ip[16], dst_ip[16];

        printf("    Src IP: %s", ip_to_str(ip->saddr, src_ip));
        printf(" → Dst IP: %s", ip_to_str(ip->daddr, dst_ip));
        printf(" | Protocol: ");

        switch (ip->protocol) {
            case 1: printf("ICMP"); break;
            case 6: printf("TCP"); break;
            case 17: printf("UDP"); break;
            default: printf("Other (%d)", ip->protocol); break;
        }

        printf(" | Length: %d bytes\n", header->len);
    } else {
        printf("    Non-IP packet (Ethertype: 0x%04X)\n", ntohs(eth->type));
    }
}

int main() {
    char iface[256];
    char errbuf[PCAP_ERRBUF_SIZE];

    FILE *f = fopen("selected_interface.txt", "r");
    if (!f) {
        printf("Run interface selector first.\n");
        return 1;
    }
    fgets(iface, sizeof(iface), f);
    iface[strcspn(iface, "\n")] = '\0';
    fclose(f);

    pcap_t *handle = pcap_open_live(iface, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    printf("🔍 Sniffing on interface: %s\n", iface);
    printf("Press Ctrl+C to stop.\n");

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
