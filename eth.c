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
	
	if (datalen<3){
		printf("dev:%s f:%s/%u t:%s/%u d:[]\n",args,src,(unsigned int)ntohs(udp->source),dst,(unsigned int)ntohs(udp->dest));
		return;
	}

enum sipstates_ {	
	SIPSTART,

	SIPSKIP_LWS,
	SIPSKIP_LINE,

	SIPRESP_CODE,
	SIPRESP_TXT,
	SIPHDR
};
	
	int state=SIPSTART;
	int postskip_state;
	int mstate=0;
	int is_resp=-1;
	char *resp_code=NULL;
	int resp_codel=0;
	char *resp_text=NULL;
	int resp_textl=0;
	
	char *type=sip;
	int typel=0;
	char *tag;
	tl_int tagl=0;
	char *cc=sip;
	int ccleft=datalen;
	int allgood=0;
	int done=0;
do { // breakable
	//////////// 
	///phase 1
	////////////
	while (ccleft){
		char c=*cc;
#define SKIPS_COMMON_CODE				\
		if (state==SIPSKIP_LWS) { 		\
			if (c==' ' || c=='\t') {	\
				cc++; 					\
				ccleft--;				\
				continue;				\
			} else {					\
				state=postskip_state;	\
				continue;				\
			}							\
		}								\
		if (state==SIPSKIP_LINE) {		\
			cc++;						\
			ccleft--;					\
			if (c=='\n') {				\
				state=postskip_state;	\
				continue;				\
			} 							\
		}								\
		
		SKIPS_COMMON_CODE;
		
		
		if (state==SIPSTART) {
			if (c==' ' || c=='\t' || c=='\n' || c=='\r') { // first break
				if (typel<3 || c=='\n' || c=='\r') { //single word in first line - not OK
					done=1;
					break;
				}
				if (type[0]=='S' && type[1]=='I' && type[2]=='P'){
					is_resp=1;
					state=SIPSKIP_LWS;
					postskip_state=SIPRESP_CODE;
					cc++;
					ccleft--;
					continue;
				} else {
					is_resp=0;
					state=SIPSKIP_LINE;
					postskip_state=SIPHDR;
					cc++;
					ccleft--;
					break; // enter directly to phase 2
				}
			} else {
				cc++;
				ccleft--;
				typel++;
				continue;
			}
		}
		if (state==SIPRESP_CODE){ //parsing the responce code
			if (c==' ' || c=='\t' || c=='\n' || c=='\r') { // break
				if(c=='\n' || c=='\r') { //we don't expect new line here :(
					done=1;
					break;
				}
				cc++;
				ccleft--;
				state=SIPSKIP_LWS;
				postskip_state=SIPRESP_TXT;
				continue;
			}
			
			
			
			cc++;
			ccleft--;
			resp_codel++;
			continue;
		}
		if (state==SIPRESP_TXT){ //parsing the responce code
			if (c==' ' || c=='\t' || c=='\n' || c=='\r') { // break
				if(c=='\n' || c=='\r') { //we don't expect new line here :(
					done=1;
					break;
				}
				cc++;
				ccleft--;
				state=SIPSKIP_LWS;
				postskip_state=SIPRESP_TXT;
				continue;
			}
			
			
			
			cc++;
			ccleft--;
			resp_codel++;
			continue;
		}
		
		
		
		done=0; break; // invalid state?
	}
	if (done || ccleft==0 || state!=SIPSKIP_LINE ) break;
	//////////// 
	///phase 2
	////////////
	while (ccleft){
		char c=*cc;
		SKIPS_COMMON_CODE;
		
	}
	
	//breakable
} while (0);
#undef SKIPS_COMMON_CODE

	printf("dev:%s f:%s/%u t:%s/%u d:[%3.3s]\n",args,src,(unsigned int)ntohs(udp->source),dst,(unsigned int)ntohs(udp->dest),sip);
	
	
}