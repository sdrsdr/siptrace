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
	SIPHDR,
	SIPSKIP_HSEP,
	SIP_FROM,
	SIP_TO
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
	
	char *from=NULL;
	int froml=0;
	
	char *to=NULL;
	int tol=0;
	
	char* hstart=NULL;
	int hstartl=0;
	
	int fromfound=0,tofound=0;
	
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
			if (c=='\n') state=postskip_state;	\
			continue;					\
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
			
			if (resp_code==NULL) resp_code=cc;
			
			cc++;
			ccleft--;
			resp_codel++;
			continue;
		}
		if (state==SIPRESP_TXT){ //parsing the responce text
			if (c=='\n' || c=='\r') { // break
				cc++;
				ccleft--;
				if (c=='\r' && ccleft && *cc=='\n'){
					cc++;
					ccleft--;
				}
				state=SIPHDR;
				hstart=cc;
				hstartl=0;
				break;
			}
			
			if (resp_text==NULL) resp_text=cc;
			
			
			cc++;
			ccleft--;
			resp_textl++;
			continue;
		}
		
		
		
		done=1; break; // invalid state?
	}
	if (done || ccleft==0 || !(state==SIPSKIP_LINE || state==SIPHDR)) break;
	//////////// 
	///phase 2
	////////////
	
	
	while (ccleft){
		char c=*cc;
		SKIPS_COMMON_CODE;
		if (state==SIPSKIP_HSEP) { 		
			if (c==' ' || c=='\t' || c==':') {	
				cc++; 					
				ccleft--;				
				continue;				
			} else {					
				state=postskip_state;	
				continue;				
			}							
		}		
		
		if (state==SIPHDR){
			if (c=='\n' || c=='\r') { // break
				cc++;
				ccleft--;
				if (c=='\r' && ccleft && *cc=='\n'){
					cc++;
					ccleft--;
				}
				if (!hstartl) { //end of sip headers
					done=1; 
					break;
				}
				//invalid but we keep parsing..
				state=SIPHDR;
				hstart=cc;
				hstartl=0;
				continue;
			}
			if (c==':' || c==' ' || c=='\t') {
				if (hstartl==2 /* && hstart[0]=='t' */ && hstart[1]=='o') {
					state=SIPSKIP_HSEP;
					postskip_state=SIP_TO;
					cc++;
					ccleft--;
					continue;
					
				}
				if (hstartl==4 /* && hstart[0]=='f' */ && hstart[1]=='r' && hstart[2]=='o' && hstart[3]=='m') {
					state=SIPSKIP_HSEP;
					postskip_state=SIP_FROM;
					cc++;
					ccleft--;
					continue;
					
				}
				//skip this line!
				hstartl=0;
				hstart=NULL;
				state=SIPSKIP_LINE;
				postskip_state=SIPHDR;
				cc++;
				ccleft--;
				continue;
			}
			hstartl++;
			if (hstartl>4 ){ //we're not interested in other than TO and FROM 
				hstartl=0;
				hstart=NULL;
				state=SIPSKIP_LINE;
				postskip_state=SIPHDR;
				cc++;
				ccleft--;
				continue;
			}
			*cc|=0x20; //lowcase 
			if (hstartl==1){
				if (!(*cc=='t' || *cc=='f' )) { //first is not t(o) or f(rom) we're not interested
					hstartl=0;
					hstart=NULL;
					state=SIPSKIP_LINE;
					postskip_state=SIPHDR;
					cc++;
					ccleft--;
					continue;
					
				}
				hstart=cc;
			}
			cc++;
			ccleft--;
			continue;
		}
		
		if (state==SIP_FROM){
			if (c=='\r' || c=='\n') {
				cc++;
				ccleft--;
				if (c=='\r' && ccleft && *cc=='\n'){
					cc++;
					ccleft--;
				}
				state=SIPHDR;
				hstartl=0;
				fromfound=1;
				if (tofound){
					allgood=1;
					done=1;
					break;
				} else continue;
			}
			if (!froml) {
				from=cc;
			}
			froml++;
			cc++;
			ccleft--;
			continue;
		}
		if (state==SIP_TO){
			if (c=='\r' || c=='\n') {
				cc++;
				ccleft--;
				if (c=='\r' && ccleft && *cc=='\n'){
					cc++;
					ccleft--;
				}
				state=SIPHDR;
				hstartl=0;
				tofound=1;
				if (fromfound){
					allgood=1;
					done=1;
					break;
				} else continue;
			}
			if (!tol) {
				to=cc;
			}
			tol++;
			cc++;
			ccleft--;
			continue;
		}
	}
	if (done) break;
	
	//breakable
} while (0);
#undef SKIPS_COMMON_CODE
	if (!allgood){
		printf("dev:%s f:%s/%u t:%s/%u ER d:[%3.3s]\n",args,src,(unsigned int)ntohs(udp->source),dst,(unsigned int)ntohs(udp->dest),sip);
	} else {
		if (is_resp){
			printf("dev:%s f:%s/%u/%u/%.*s t:%s/%u/%u/%.*s RS tx:%.*s c:%.*s\n",args,src,(unsigned int)ntohs(udp->source),froml,froml,from,dst,(unsigned int)ntohs(udp->dest),tol,tol,to,resp_textl,resp_text,resp_codel,resp_code);
		} else {
			printf("dev:%s f:%s/%u/%u/%.*s t:%s/%u/%u/%.*s RQ tx:%.*s\n",args,src,(unsigned int)ntohs(udp->source),froml,froml,from,dst,(unsigned int)ntohs(udp->dest),tol,tol,to,typel,type);
		}
	}
	
}