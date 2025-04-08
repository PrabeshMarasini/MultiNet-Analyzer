#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

typedef struct {
    char ip[20];
    char mac[18];
} Device;

Device devices[MAX_IP];
int deviceCount = 0;

char myIP[20];
char myMAC[18];
char gatewayIP[20];
char gatewayMAC[18];

CRITICAL_SECTION cs;

int get_mac_address(const char *ip, char *mac) {
    IPAddr destIP;
    ULONG macAddr[2];
    ULONG macAddrLen = 6;
    memset(macAddr, 0, sizeof(macAddr));

    destIP = inet_addr(ip);
    if (SendARP(destIP, 0, macAddr, &macAddrLen) == NO_ERROR) {
        unsigned char *macBytes = (unsigned char *)macAddr;
        sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                macBytes[0], macBytes[1], macBytes[2],
                macBytes[3], macBytes[4], macBytes[5]);
        return 1;
    }
    return 0;
}

void get_local_ip_and_mac() {
    PIP_ADAPTER_INFO adapterInfo;
    DWORD size = sizeof(IP_ADAPTER_INFO);
    adapterInfo = (IP_ADAPTER_INFO *)malloc(size);

    if (GetAdaptersInfo(adapterInfo, &size) == ERROR_BUFFER_OVERFLOW) {
        free(adapterInfo);
        adapterInfo = (IP_ADAPTER_INFO *)malloc(size);
    }

    if (GetAdaptersInfo(adapterInfo, &size) == NO_ERROR) {
        PIP_ADAPTER_INFO current = adapterInfo;
        while (current) {
            // Skip invalid or virtual adapters
            if (
                strcmp(current->IpAddressList.IpAddress.String, "0.0.0.0") != 0 &&
                strncmp(current->IpAddressList.IpAddress.String, "169.254", 7) != 0 &&
                strcmp(current->GatewayList.IpAddress.String, "0.0.0.0") != 0
            ) {
                strcpy(myIP, current->IpAddressList.IpAddress.String);
                sprintf(myMAC, "%02X:%02X:%02X:%02X:%02X:%02X",
                        current->Address[0], current->Address[1], current->Address[2],
                        current->Address[3], current->Address[4], current->Address[5]);

                strcpy(gatewayIP, current->GatewayList.IpAddress.String);
                get_mac_address(gatewayIP, gatewayMAC);
                break;
            }
            current = current->Next;
        }
    }

    free(adapterInfo);
}

DWORD WINAPI scan_ip(LPVOID param) {
    ThreadData *data = (ThreadData *)param;
    char mac[18];

    if (get_mac_address(data->ip, mac)) {
        EnterCriticalSection(&cs);
        strcpy(devices[deviceCount].ip, data->ip);
        strcpy(devices[deviceCount].mac, mac);
        deviceCount++;
        LeaveCriticalSection(&cs);
    }

    free(data);
    return 0;
}

void print_device(const char *label, const char *ip, const char *mac) {
    printf("%s:\n", label);
    printf("  IP  : %s\n", ip);
    printf("  MAC : %s\n\n", mac);
}

int normalize_mac(const char *src, char *normalized) {
    int j = 0;
    for (int i = 0; src[i] != '\0'; i++) {
        if (src[i] != '-' && src[i] != ':') {
            normalized[j++] = toupper(src[i]);
        }
    }
    normalized[j] = '\0';
    return j;
}

int is_same_mac(const char *mac1, const char *mac2) {
    char norm1[13], norm2[13];
    normalize_mac(mac1, norm1);
    normalize_mac(mac2, norm2);
    return strcmp(norm1, norm2) == 0;
}

int main() {
    char subnet[16];
    printf("Enter subnet (e.g., 192.168.1): ");
    scanf("%15s", subnet);

    InitializeCriticalSection(&cs);
    get_local_ip_and_mac();

    printf("\nDetected Your Device:\n");
    printf("  IP  : %s\n", myIP);
    printf("  MAC : %s\n", myMAC);

    printf("Detected Gateway:\n");
    printf("  IP  : %s\n", gatewayIP);
    printf("  MAC : %s\n\n", gatewayMAC);

    printf("Scanning subnet %s.0...\n\n", subnet);

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

    printf("\nScan Complete!\n\n");

    int printedOthers = 0;
    for (int i = 0; i < deviceCount; i++) {
        if (strcmp(devices[i].ip, myIP) == 0 || is_same_mac(devices[i].mac, myMAC)) {
            print_device("Your Device", devices[i].ip, devices[i].mac);
        } else if (strcmp(devices[i].ip, gatewayIP) == 0 || is_same_mac(devices[i].mac, gatewayMAC)) {
            print_device("Gateway Device", devices[i].ip, devices[i].mac);
        } else {
            if (!printedOthers) {
                printf("Other Devices:\n");
                printedOthers = 1;
            }
            printf("  IP  : %s\n", devices[i].ip);
            printf("  MAC : %s\n\n", devices[i].mac);
        }
    }

    DeleteCriticalSection(&cs);
    return 0;
}
