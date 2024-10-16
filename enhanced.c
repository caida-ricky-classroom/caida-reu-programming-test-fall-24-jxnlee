#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct iphdr *ip_header;
    int packet_count = 0;

	// nitialize octet count array to 0 to keep track of the amount of each octet with the index corresponding to each octet
	int octet_count[256] = {0}; 

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

	// store ip address in variable
	struct in_addr* addr = (struct in_addr*) &ip_header->daddr;

	// get the octet of the ip address by accessing the last byte of the ip address
	int octet = ((unsigned char*)addr)[3];

	// increment the int in the position of the octet value in the octet count array
	octet_count[octet]++;

	// modified code to print ip destination (commented out for this implementation)
	// printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(*addr));
    }

	// print out the octet and their corresponding occurrence from the index in the array
	for (int i = 0; i < 256; i++)
		printf("Last Octet %d: %d\n", i, octet_count[i]);

    pcap_close(handle);
    return 0;
}
