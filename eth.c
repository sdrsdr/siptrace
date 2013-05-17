#include <stdlib.h>
#include <stdio.h>


#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <arpa/inet.h>
#include <string.h>


#include "analyzers.h"
#include "tagbulk.h"

#define ETHERTYPE_IP_L 8 


void  onpacket_eth (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	if (header->caplen<sizeof(struct ether_header)){
		fprintf(stderr,"dev: %s csz: %d sub ethernet header packet size!!\n",args, header->caplen);
		return;
	}
	
	struct ether_header *eth=(struct ether_header *)packet;
	
	if (eth->ether_type!=ETHERTYPE_IP_L){
		fprintf(stderr,"dev: %s csz: %d et:%d not a IP packet!!!\n",args, header->caplen,eth->ether_type);
		return;
	} 
	
	if (header->caplen<sizeof(struct ether_header)+sizeof(struct iphdr)){
		fprintf(stderr,"dev: %s csz: %d sub ip header packet size!!\n",args, header->caplen);
		return;
	}
	
	struct iphdr *ip=(struct iphdr *)(eth+1);
	u_int32_t *ip_payload=(u_int32_t *)ip;
	
	if (ip->version!=4) {
		fprintf(stderr,"dev: %s csz: %d et:%d ipv:%d not a IPv4 packet!!!\n",args, header->caplen,eth->ether_type,ip->version);
		return;
	}
	
	if (ip->protocol!=SOL_UDP){
		fprintf(stderr,"dev: %s csz: %d et:%d ipv:%d ipprot:%d not a UDP packet!!!\n",args, header->caplen,eth->ether_type,ip->version,(int)ip->protocol);
		return;
	}
	
	int datalen=header->caplen-(sizeof(struct ether_header)+4*ip->ihl+sizeof(struct udphdr));
	if (datalen<0){
		fprintf(stderr,"dev: %s csz: %d ihl:%d sub UDP header packet size!!\n",args, header->caplen,(int)ip->ihl);
		return;
	}
		
	struct udphdr *udp=(struct udphdr *)(ip_payload+ip->ihl);
	char *sip=(char *)(udp+1);
	
	char src[INET_ADDRSTRLEN+2];
	char dst[INET_ADDRSTRLEN+2];
	src[INET_ADDRSTRLEN+1]=0;
	dst[INET_ADDRSTRLEN+1]=0;
	
	inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN+1);
	inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN+1);
	
	onpacket_sip (sip, datalen,args, src ,dst, (unsigned int)ntohs(udp->source),(unsigned int)ntohs(udp->dest) );
}