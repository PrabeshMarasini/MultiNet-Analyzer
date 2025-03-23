#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <pcap.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAX_IP 254

// Function to send an ICMP Echo Request (Ping)
int ping(const char *ip) {
    char command[64];
    snprintf(command, sizeof(command), "ping -n 1 -w 100 %s > nul", ip);
    return (system(command) == 0);
}

// Function to retrieve MAC address via ARP request
int get_mac_address(const char *ip, char *mac) {
    IPAddr destIP;
    ULONG macAddr[2];
    ULONG macAddrLen = 6;
    memset(macAddr, 0, sizeof(macAddr));

    destIP = inet_addr(ip);
    if (SendARP(destIP, 0, macAddr, &macAddrLen) == NO_ERROR) {
        unsigned char *macBytes = (unsigned char *)macAddr;
        sprintf(mac, "%02X-%02X-%02X-%02X-%02X-%02X", 
                macBytes[0], macBytes[1], macBytes[2], 
                macBytes[3], macBytes[4], macBytes[5]);
        return 1;
    }
    return 0;
}

int main() {
    char subnet[16];
    printf("Enter subnet (e.g., 192.168.1): ");
    scanf("%15s", subnet);

    printf("Scanning subnet %s.0...\n", subnet);

    for (int i = 1; i <= MAX_IP; i++) {
        char ip[20], mac[18];
        snprintf(ip, sizeof(ip), "%s.%d", subnet, i);
        printf("Scanning %s...\n", ip);

        if (ping(ip)) {
            printf("Active (Ping): %s\n", ip);
        }
        
        if (get_mac_address(ip, mac)) {
            printf("  MAC Address: %s\n", mac);
        }
    }
    return 0;
}
