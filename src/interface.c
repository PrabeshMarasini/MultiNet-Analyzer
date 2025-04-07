#include <pcap.h>
#include <stdio.h>

void list_interfaces() {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }

    printf("Available interfaces:\n");
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }

    if (i == 0) {
        printf("No interfaces found. Check Npcap installation.\n");
        return;
    }

    int choice;
    printf("Select interface number: ");
    scanf("%d", &choice);

    d = alldevs;
    for (i = 1; i < choice && d; d = d->next, i++);

    if (d) {
        printf("You selected: %s\n", d->name);
        FILE *f = fopen("selected_interface.txt", "w");
        if (f) {
            fprintf(f, "%s\n", d->name);
            fclose(f);
        }
    } else {
        printf("Invalid selection.\n");
    }

    pcap_freealldevs(alldevs);
}

int main() {
    list_interfaces();
    return 0;
}
