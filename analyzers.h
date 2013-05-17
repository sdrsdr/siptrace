#ifndef siptrace_analysers_h
#define siptrace_analysers_h

#include <pcap/pcap.h>

#include "tagbulk.h"

#ifdef __cplusplus
extern "C" {
#endif


#ifndef siptrace_analysers_h_externals_here
#define siptrace_analysers_h_external extern
#else 
#define siptrace_analysers_h_external 
#endif

siptrace_analysers_h_external pcap_t *handle;
siptrace_analysers_h_external int linklayer;
siptrace_analysers_h_external int sigquit;
siptrace_analysers_h_external tagbulkhead *ignoretags;
siptrace_analysers_h_external tagbulkhead *calltags;
siptrace_analysers_h_external unsigned packets_captured;

siptrace_analysers_h_external int showall;


void onpacket_eth (u_char *args, const struct pcap_pkthdr *header, const u_char *packet); //in eth.c

void onpacket_sip (u_char *sippacket, int datalen,char *dev, char* srca , char *dsta, unsigned int srcp, unsigned int dstp );//in sip.c

#ifdef __cplusplus
//extern "C" {
}
#endif
#endif
