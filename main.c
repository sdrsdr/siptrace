#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <getopt.h>

#include <pcap/pcap.h>


#define siptrace_analysers_h_externals_here

#include "analyzers.h"



static void onint(int signal) {
	if (signal==SIGALRM){
		time_t now=time(NULL);
		tb_ttl_check(ignoretags,now);
		tb_ttl_check(calltags,now);
		alarm(2);
		//fprintf(stderr,"A!");
		return;
	}
	if (signal==SIGQUIT){
		sigquit++;
		fprintf(stderr,"'\nDEBUG: tagbulk extends:%d(i),%d(c) packets:%d\n",ignoretags->expands,calltags->expands,packets_captured);
		return;
	}
    pcap_breakloop(handle);
}

int main(int argc, char *argv[]) {
	sigquit=0;
	ignoretags=tb_create();
	calltags=tb_create();
	char *dev=NULL;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "udp and port 5060";	/* The filter expression */
	char *filter=filter_exp;
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	
	showall=0;packets_captured=0;
	
	struct option long_options[] = {
		{"dev", required_argument,       0, 'i'},
		{"all",   no_argument,       0, 'a'},
		{0, 0, 0, 0}
	};
	
	int c; int loidx=-1; 
	optind=1;
	
	while ((c = getopt_long (argc, argv, ":i:a",long_options,&loidx)) != -1){
		switch (c)	{
		case 'a':
			showall = 1;
			break;
		case 'i':
			dev = optarg;
			break;
		case ':':
			if (optopt == 'i') {
				if (loidx!=-1){
					fprintf (stderr, "Option --dev requires an device name as argument.\n");
				} else fprintf (stderr, "Option -i requires an device name as argument.\n");
			} else {
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
			}
			return 1;
		case '?': 
			goto end_of_options;
			break;
		default:
			abort ();
		}
		loidx=-1;
	}
end_of_options:;

	/* Define the device */
	if (dev==NULL) {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s (are you root?)\n", errbuf);
			return(2);
		}
	}
	
	
	if (optind<argc) {

		int  i ; 
		int  size_total = 0;
		size_t *lens=(size_t *)malloc((argc)*sizeof(size_t));
		for (i=optind;i < argc; i++) {
			lens[i]=strlen(argv[i]);
			size_total += lens[i]+1;
		}
		filter = (char*)malloc(size_total);
		char *start=filter;
		for (i=optind;i < argc; i++) {
			memcpy(start, argv[i], lens[i]);
			start+=lens[i];
			*start=' ';
			start++;
		}
		start--;
		*start=0;
		free(lens);
		
	}
	
	if (showall){
		fprintf (stderr, "Notice: Option -a/--all  found! You will see summary for all SIP packets captured on device %s and filtered [%s].\n",dev,filter);
	} else {
		fprintf (stderr, "Notice: You will see only calls establishment/teradown from all SIP packets captured on device %s and filtered [%s]\n",dev,filter);
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
	//fprintf(stderr, "Device %s  opened link type is: %d\n", dev, linklayer);

 	
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse pcap filter %s: %s\n", filter, pcap_geterr(handle));
		return(2);
	} 
	
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install pcap filter %s: %s\n", filter, pcap_geterr(handle));
		return(2);
	}
	
	//fprintf(stderr, "Using pcap filter %s\n", filter );
	
	
	if (signal(SIGINT, onint) == SIG_ERR) {
		fprintf(stderr, "An error occurred while setting a signal handler.\n");
		return 2;
	}
	if (signal(SIGTERM,onint) == SIG_ERR) {
		fprintf(stderr, "An error occurred while setting a signal handler.\n");
		return 2;
	}
	
	if (signal(SIGQUIT,onint) == SIG_ERR) {
		fprintf(stderr, "An error occurred while setting a signal handler.\n");
		return 2;
	}
    
	if (signal(SIGALRM,onint) == SIG_ERR) {
		fprintf(stderr, "An error occurred while setting a signal handler.\n");
		return 2;
	}
    
	alarm(2);

	/* Grab packet loop */
	if (linklayer==DLT_EN10MB){
		pcap_loop(handle, -1,  onpacket_eth, (u_char *)dev);
	} else {
		fprintf(stderr, "Unsupported link layer %d!.\n",linklayer);
		return 2;
	}

	fprintf(stderr,"\ncapture loop ended!\n");
	/* And close the session */
	pcap_close(handle);
	return(0);
}