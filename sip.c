#include <stdlib.h>
#include <stdio.h>


#include <string.h>


#include "analyzers.h"
#include "tagbulk.h"

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


void  onpacket_sip (time_t now, char *sippacket, int datalen,char *dev, char* srca , char *dsta, unsigned int srcp, unsigned int dstp ) {
	packets_captured++;
	
	if (datalen<3){
		printf("t:%lld dev:%s f:%s/%u t:%s/%u d:[]\n",(long long)now,dev,srca,srcp,dsta,dstp);
		fflush(stdout);
		return;
	}

	
	int state=SIPSTART;
	int postskip_state;
	int is_resp=-1;
	char *resp_code=NULL;
	int resp_codel=0;
	char *resp_text=NULL;
	int resp_textl=0;
	
	char *type=(char *)sippacket;
	int typel=0;
	
	char *cc=(char *)sippacket;
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
	int postgt=0;
	char *fromtagstart=NULL;
	char *fromtagend=NULL;
	int fromtagstartl=0;
	
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
				if (hstartl==2 /* && hstart[0]=='t' */ && hstart[1]=='o' && !tofound) {
					state=SIPSKIP_HSEP;
					postskip_state=SIP_TO;
					cc++;
					ccleft--;
					continue;
					
				}
				if (hstartl==4 /* && hstart[0]=='f' */ && hstart[1]=='r' && hstart[2]=='o' && hstart[3]=='m' && !fromfound) {
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
				if (fromtagstart && !fromtagend) fromtagend=cc-1;
				if (fromtagstart) fromtagstartl=fromtagend-fromtagstart+1;
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
			if (c=='>') postgt=1;
			else if (c=='=' && postgt && froml>5 && cc[-4]==';' && cc[-3]=='t' && cc[-2]=='a' && cc[-1]=='g' ) {
				fromtagstart=cc+1;
			} else if (c==';' && fromtagstart && !fromtagend){
				fromtagend=cc-1;
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
		if (datalen<=4){  //hide keep-alives
			return;
		}
		if (fromtagstartl<MAXTAGSIZE) { //hide responces to hidden requests
			if (tb_find_and_set_ttl(ignoretags,fromtagstart,fromtagstartl,now+2)){
				return;
			}
		}
		if (showall){
			printf("T:%lld DEV:%s FROM:%s/%u TO:%s/%u ER D:[%3.3s] SZ:%u\n",(long long)now,dev,srca,srcp,dsta,dstp,sippacket,datalen);
			fflush(stdout);
		}
	} else {
		if (is_resp){
			if (!showall){
				if (tb_find_and_set_ttl(ignoretags,fromtagstart,fromtagstartl,now+2)) return;
				tagelem* tage=tb_find (calltags,fromtagstart,fromtagstartl,NULL);
				if (tage && resp_codel==3){ //this is a valid responce from a known call
					#define respcodeis(a,b,c) (resp_code[0]==a && resp_code[1]==b && resp_code[2]==c)
					tage->lastcode[0]=resp_code[0];
					tage->lastcode[1]=resp_code[1];
					tage->lastcode[2]=resp_code[2];
					if (
						respcodeis ('4','0','1') 
						|| respcodeis ('1','8','0') 
						|| respcodeis ('1','8','3')
						|| respcodeis ('1','0','0')
						|| respcodeis ('4','8','7')
					){
						tage->ttl=now+120;
						return;
					}
					if (respcodeis ('2','0','0') ){
						if (tage->gotfinal) return;
						tage->gotfinal=1; //show
					}
					#undef respcodeis
				}
			}
			printf("T:%lld DEV:%s FROM:%s/%u/%u/%.*s FTAG:%.*s TO:%s/%u/%u/%.*s RS TXT:%.*s CODE:%.*s\n",(long long)now,dev,srca,srcp,froml,froml,from,fromtagstartl,fromtagstart,dsta,dstp,tol,tol,to,resp_textl,resp_text,resp_codel,resp_code);
			fflush(stdout);
		} else {
			if (fromtagstartl<MAXTAGSIZE) {
				if (typel==9 && memcmp(type,"SUBSCRIBE",9)==0){
					if (!showall) {
						tb_find_or_add(ignoretags,fromtagstart,fromtagstartl,now+30);
						return;
					}
				}
				if (typel==8 && memcmp(type,"REGISTER",8)==0){//hide register rq
					if (!showall) {
						tb_find_or_add(ignoretags,fromtagstart,fromtagstartl,now+30);
						return;
					}
				}
				if (typel==7 && memcmp(type,"OPTIONS",7)==0){//hide options rq
					if (!showall){
						tb_find_or_add(ignoretags,fromtagstart,fromtagstartl,now+30);
						return;
					}
				}
				if (typel==6) {
					if (memcmp(type,"INVITE",6)==0){//show invite rq/rs
						if (!showall){
							tagelem* tage;
							if (tb_find_or_add_ex(calltags,fromtagstart,fromtagstartl,now+120,&tage)) {
								tage->printblob=0;
								if (tage->blob) {
									free(tage->blob);
									tage->blob=NULL;
								}
								return; //we have already shown this
							}
						}
					} else if (memcmp(type,"CANCEL",6)==0){
						if (!showall){
							tagelem* tage;
							if (tb_find_and_set_ttl_ex(calltags,fromtagstart,fromtagstartl,now+10,&tage)) {
								tage->gotfinal=1;
								tage->printblob=0;
								if (tage->blob) {
									free(tage->blob);
									tage->blob=NULL;
								}
							}
						}
					} else if (memcmp(type,"NOTIFY",6)==0){//hide
						if (!showall) {
							tb_find_or_add(ignoretags,fromtagstart,fromtagstartl,now+30);
							return;
						}
					}
				}
				if (typel==4 && memcmp(type,"INFO",4)==0){ //hide
					if (!showall) {
						tb_find_or_add(ignoretags,fromtagstart,fromtagstartl,now+30);
						return;
					}
				}
				if (typel==3 && memcmp(type,"ACK",3)==0){
					tagelem* tage;
					if (!showall){
						if (tb_find_and_set_ttl_ex(calltags,fromtagstart,fromtagstartl,now+5,&tage)) {
							if (tage->gotfinal){
								//we have printed the final info for this call
								return;
							}
							if (tage->lastcode[0]=='4' && tage->lastcode[1]=='0' && tage->lastcode[2]=='1') {
								//make a blob and hid this one as we expect autorative invati in a spltsecond :)
								tage->printblob=1;
								if (tage->blob) free(tage->blob);
								tage->blob=mkblob(now,dev,srca,srcp,froml,from,fromtagstartl,fromtagstart,dsta,dstp,tol,to,typel,type);
								return;
							} else {
								printf("T:%lld DEV:%s FROM:%s/%u/%u/%.*s FTAG:%.*s TO:%s/%u/%u/%.*s RQ TXT:%.*s LC:%.3s\n",(long long)now,dev,srca,srcp,froml,froml,from,fromtagstartl,fromtagstart, dsta,dstp,tol,tol,to,typel,type,tage->lastcode);
								fflush(stdout);
							}
							return; 
						}
					} else {
						tage=tb_find (calltags,fromtagstart,fromtagstartl,NULL);
						if (tage) {
							printf("T:%lld DEV:%s FROM:%s/%u/%u/%.*s FTAG:%.*s TO:%s/%u/%u/%.*s RQ TXT:%.*s LC:%.3s\n",(long long)now,dev,srca,srcp,froml,froml,from,fromtagstartl,fromtagstart, dsta,dstp,tol,tol,to,typel,type,tage->lastcode);
							fflush(stdout);
							return;
						}
					}
				}
			}
			printf("T:%lld DEV:%s FROM:%s/%u/%u/%.*s FTAG:%.*s TO:%s/%u/%u/%.*s RQ TXT:%.*s\n",(long long)now,dev,srca,srcp,froml,froml,from,fromtagstartl,fromtagstart, dsta,dstp,tol,tol,to,typel,type);
			fflush(stdout);
		}
	}
	
	
	
}