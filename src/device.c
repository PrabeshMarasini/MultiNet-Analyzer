
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAX_IP 254
#define MAX_THREADS 50

typedef struct {
    char ip[20];
} ThreadData;

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

DWORD WINAPI scan_ip(LPVOID param) {
    ThreadData *data = (ThreadData *)param;
    char mac[18];

    if (get_mac_address(data->ip, mac)) {
        printf("Active Host: %s | MAC: %s\n", data->ip, mac);
    }

    free(data);  
    return 0;
}

int main() {
    char subnet[16];
    printf("Enter subnet (e.g., 192.168.1): ");
    scanf("%15s", subnet);

    printf("Scanning subnet %s.0...\n", subnet);

    HANDLE threads[MAX_THREADS];  
    int threadCount = 0;

    for (int i = 1; i <= MAX_IP; i++) {
        char ip[20];
        snprintf(ip, sizeof(ip), "%s.%d", subnet, i);

        ThreadData *data = (ThreadData *)malloc(sizeof(ThreadData));
        if (!data) {
            fprintf(stderr, "Memory allocation failed\n");
            break;
        }
        strcpy(data->ip, ip);

        threads[threadCount] = CreateThread(NULL, 0, scan_ip, data, 0, NULL);
        if (threads[threadCount] == NULL) {
            fprintf(stderr, "Failed to create thread for %s\n", ip);
            free(data);
        } else {
            threadCount++;
        }

        if (threadCount >= MAX_THREADS) {
            WaitForMultipleObjects(threadCount, threads, TRUE, INFINITE);
            threadCount = 0;  
        }
    }

    WaitForMultipleObjects(threadCount, threads, TRUE, INFINITE);

    printf("Scanning complete.\n");
    return 0;
}
