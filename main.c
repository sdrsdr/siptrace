#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pcap/pcap.h>

#include <signal.h>

#define siptrace_analysers_h_externals_here

#include "analyzers.h"



static void onint(int signal) {
    pcap_breakloop(handle);
}

int main(int argc, char *argv[]) {
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "udp and port 5060";	/* The filter expression */
	char *filter=filter_exp;
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s (are you root?)\n", errbuf);
		return(2);
	}
	
	if (argc>1) {
		dev=argv[1];
	}
	
	if (argc>2) {

		int  i ; 
		int  size_total = 0;
		size_t *lens=(size_t *)malloc((argc)*sizeof(size_t));
		for (i=2;i < argc; i++) {
			lens[i]=strlen(argv[i]);
			size_total += lens[i]+1;
		}
		filter = (char*)malloc(size_total);
		char *start=filter;
		for (i=2;i < argc; i++) {
			memcpy(start, argv[i], lens[i]);
			start+=lens[i];
			*start=' ';
			start++;
		}
		start--;
		*start=0;
		free(lens);
		
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in non promiscuous mode */
	handle = pcap_open_live(dev, 4096, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	linklayer=pcap_datalink(handle);
	fprintf(stderr, "Device %s  opened link type is: %d\n", dev, linklayer);

 	
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
		return(2);
	}
	
	if (signal(SIGINT, onint) == SIG_ERR) {
        fprintf(stderr, "An error occurred while setting a signal handler.\n");
        return 2;
    }
    if (signal(SIGTERM,onint) == SIG_ERR) {
        fprintf(stderr, "An error occurred while setting a signal handler.\n");
        return 2;
    }
	/* Grab packet loop */
	if (linklayer==DLT_EN10MB){
		pcap_loop(handle, -1,  onpacket_eth, (u_char *)dev);
	} else {
		fprintf(stderr, "Unsupported link layer!.\n");
		return 2;
	}

	printf("loop ended!\n");
	/* And close the session */
	pcap_close(handle);
	return(0);
}