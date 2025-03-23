#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <iphlpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

int get_gateway_mac_address(const char *ip, char *mac) {
    IPAddr destIP = inet_addr(ip);
    ULONG macAddr[2] = {0};
    ULONG macAddrLen = 6;

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
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, NULL, &bufferSize);

    PIP_ADAPTER_ADDRESSES adapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    if (!adapterAddresses) {
        printf("Memory allocation failed\n");
        return 1;
    }

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, adapterAddresses, &bufferSize) != NO_ERROR) {
        printf("Failed to get adapter addresses\n");
        free(adapterAddresses);
        return 1;
    }

    PIP_ADAPTER_ADDRESSES adapter = adapterAddresses;
    while (adapter) {
        PIP_ADAPTER_GATEWAY_ADDRESS_LH gateway = adapter->FirstGatewayAddress;
        if (gateway) {
            SOCKADDR_IN *sockAddr = (SOCKADDR_IN *)gateway->Address.lpSockaddr;
            char gatewayIP[16];
            char gatewayMAC[18];

            strcpy(gatewayIP, inet_ntoa(sockAddr->sin_addr));
            printf("Gateway IP: %s\n", gatewayIP);

            if (get_gateway_mac_address(gatewayIP, gatewayMAC)) {
                printf("Gateway MAC: %s\n", gatewayMAC);
            } else {
                printf("Failed to get gateway MAC address\n");
            }
            break;
        }
        adapter = adapter->Next;
    }

    free(adapterAddresses);
    return 0;
}
