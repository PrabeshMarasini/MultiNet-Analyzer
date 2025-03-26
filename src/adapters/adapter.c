#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <iphlpapi.h>
#include <string.h>

#pragma comment(lib, "iphlpapi.lib")

void listNetworkDevices() {
    PIP_ADAPTER_INFO adapterInfo;
    PIP_ADAPTER_INFO adapter = NULL;
    DWORD dwSize = 0;
    int deviceNumber = 1;

    if (GetAdaptersInfo(NULL, &dwSize) == ERROR_BUFFER_OVERFLOW) {
        adapterInfo = (PIP_ADAPTER_INFO)malloc(dwSize);
    }

    if (GetAdaptersInfo(adapterInfo, &dwSize) == NO_ERROR) {
        adapter = adapterInfo;
        while (adapter) {
            printf("%d. Interface Name: %s\n", deviceNumber, adapter->AdapterName);
            printf("   Description: %s\n", adapter->Description);

            if (adapter->IpAddressList.IpAddress.String[0] != '\0') {
                printf("   IPv4 Address: %s\n", adapter->IpAddressList.IpAddress.String);
            }

            printf("   MAC Address: ");
            for (int i = 0; i < adapter->AddressLength; i++) {
                printf("%02X", adapter->Address[i]);
                if (i != adapter->AddressLength - 1) {
                    printf(":");
                }
            }
            printf("\n\n");

            adapter = adapter->Next;
            deviceNumber++;
        }
    } else {
        printf("Error retrieving adapter information.\n");
    }

    if (adapterInfo) {
        free(adapterInfo);
    }
}

int main() {
    listNetworkDevices();
    return 0;
}
