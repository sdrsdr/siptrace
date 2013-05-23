#include <stdlib.h>
#include "tagbulk.h"
#include <string.h>

#include <arpa/inet.h>
#include <stdio.h>

tagbulkhead * tb_create() {
	tagbulkhead *tb=malloc(sizeof(tagbulkhead)+sizeof(tagelem)*TAGBULKSIZE);
	if (!tb) return NULL;
	tb->used=NULL;
	tb->free=(tagelem *)(tb+1);
	tb->free[TAGBULKSIZE-1].next=0;
	tb->expands=1;
#ifdef tbdebug
	tb->bulks[0]=tb->free;
#endif
	
	for (int x=0; x<TAGBULKSIZE-1; x++){
		tb->free[x].next=tb->free+(x+1);
	}
		 
	return tb;
}

tagelem* tb_expand(tagbulkhead * tb){
	tagelem * nb=malloc(sizeof(tagelem)*TAGBULKSIZE);
	nb[TAGBULKSIZE-1].next=0;
	for (int x=0; x<TAGBULKSIZE-1; x++){
		nb[x].next=nb+(x+1);
	}
	tb->free=nb;
	tb->expands++;
#ifdef tbdebug
	if (tb->expands>=DBG_MAX_EXPANDS){
		printf ("DBG_MAX_EXPANDS reached @ "__FILE__":%d\n",__LINE__);
		exit (-1);
	} else {
		tb->bulks[tb->expands-1]=nb;
	}
#endif
	return nb;
	
}

#define tb_free_el(tagel) \
	if (tagel->blob) {\
		free (tagel->blob);\
		tagel->blob=NULL;\
	}\
	tagel->ttl=0;\
	tagel->printblob=0;\
	tagel->gotfinal=0;

tagelem * tb_get_free(tagbulkhead *tb){
	time_t now=time(NULL);
	if (tb->last_ttl_check+2<now){
		tb->last_ttl_check=now;
		tb_ttl_check(tb,now);
	}
	tagelem *fe;
	if (tb->free) {
		fe=tb->free;
	} else {
		fe=tb_expand(tb);
	}
	fe->blob=NULL;
	fe->ttl=0;
	fe->printblob=0;
	fe->gotfinal=0;
	
	tb->free=fe->next;
	fe->next=tb->used;
	tb->used=fe;
	return fe;
}

void tb_ttl_check(tagbulkhead *tb,time_t now){
	if (!tb->used) return ;
	tagelem **prevup=&tb->used;
	tagelem *cu=tb->used;
	while (cu){
		if (cu->ttl>0 && cu->ttl<now){
			#ifdef tbdebug
			cu->tag[0]=0;
			#endif
			
			//store next
			tagelem *nextu=cu->next;
			
			//move cu to free
			*prevup=cu->next;
			cu->next=tb->free;
			tb->free=cu;
			
			if (cu->blob && cu->printblob){
				cu->printblob=0;
				blob_t *b=cu->blob;
				printf("T:%lld DEV:%s FROM:%s/%u/%u/%.*s FTAG:%s TO:%s/%u/%u/%.*s RQ TXT:%s LC:%.3s\n",(long long)b->at,b->dev,b->srca,b->srcp,b->froml,b->froml,b->from,b->fromtagstart, b->dsta,b->dstp,b->tol,b->tol,b->to,b->type,cu->lastcode);
			}
			tb_free_el (cu);
			
			//get next from stored
			cu=nextu;
			continue;
		}
		prevup=&(cu->next);
		cu=cu->next;
	}
}

tagelem* tb_find (tagbulkhead *tb,char *tag,tl_int size, tagelem ***prevp){
	if (!tb->used) return NULL;
	if (prevp) *prevp=&tb->used;
	tagelem *cu=tb->used;
	while (cu){
		if (size==cu->sz && memcmp(tag,cu->tag,size)==0) return cu;
		cu=cu->next;
		if (prevp) *prevp=&(cu->next);
	}
	return NULL;
}

void tb_free (tagbulkhead *tb,tagelem *tagel, tagelem **prevp){
	tb_free_el (tagel);
	
	*prevp=tagel->next;
	tagel->next=tb->free;
	tb->free=tagel;
}

int tb_find_and_free(tagbulkhead *tb,char *tag,tl_int size){
	if (!tb->used) return 0;
	tagelem **prevup=&tb->used;
	tagelem *cu=tb->used;
	while (cu){
		if (size==cu->sz && memcmp(tag,cu->tag,size)==0){
			#ifdef tbdebug
			cu->tag[0]=0;
			#endif
			*prevup=cu->next;
			cu->next=tb->free;
			tb->free=cu;
			tb_free_el(cu);
			return 1;
		}
		prevup=&(cu->next);
		cu=cu->next;
	}
	return 0;
}

int tb_find_and_set_ttl_ex(tagbulkhead *tb,char *tag,tl_int size, time_t newttl,tagelem **ret ){
	if (!tb->used) return 0;
	tagelem *cu=tb->used;
	while (cu){
		if (size==cu->sz && memcmp(tag,cu->tag,size)==0){
			cu->ttl=newttl;
			cu->printblob=0;
			if (ret) *ret=cu;
			return 1;
		}
		cu=cu->next;
	}
	return 0;
}

int tb_find_or_add_ex(tagbulkhead *tb,char *tag,tl_int size, time_t ttl,tagelem **ret ){
	tagelem *cu;
	if (tb->used) {;
		cu=tb->used;
		while (cu){
			if (size==cu->sz && memcmp(tag,cu->tag,size)==0){
				cu->ttl=ttl;
				if (ret) *ret=cu;
				return 1;
			}
			cu=cu->next;
		}
	}
	cu=tb_get_free(tb);
	cu->sz=size;
	cu->ttl=ttl;
	cu->lastcode[0]='N';
	cu->lastcode[1]='/';
	cu->lastcode[2]='A';
	memcpy(cu->tag,tag,size);
	
	if (ret) *ret=cu;
	
	return 0;
}

blob_t *mkblob(	
	time_t at,char *dev, char *srca, unsigned int srcp,
	int froml,char *from,
	int fromtagstartl,char *fromtagstart,
	char *dsta, unsigned int dstp,
	int tol, char *to,
	int typel, char *type
){
	int devl=strlen(dev);
	blob_t *b=malloc(sizeof(blob_t)+devl+2*(INET_ADDRSTRLEN+1)+froml+fromtagstartl+tol+typel+6);

	if (!b) return NULL;
	b->at=at;
	b->dstp=dstp;
	b->srcp=srcp;
	b->froml=froml;
	b->tol=tol;
	
	char *data=(char *)(b+1);
	
	b->dev=data;
	memcpy(b->dev,dev,devl); data+=devl; *data=0; data++;
	
	b->srca=data;
	memcpy(b->srca,srca,INET_ADDRSTRLEN); data+=INET_ADDRSTRLEN; *data=0; data++;
	
	b->dsta=data;
	memcpy(b->dsta,dsta,INET_ADDRSTRLEN); data+=INET_ADDRSTRLEN; *data=0; data++;
	
	b->from=data;
	memcpy(b->from,from,froml); data+=froml; *data=0; data++;
	
	b->to=data;
	memcpy(b->to,to,tol); data+=tol; *data=0; data++;

	b->fromtagstart=data;
	memcpy(b->fromtagstart,fromtagstart,fromtagstartl); data+=fromtagstartl; *data=0; data++;
	
	b->type=data;
	memcpy(b->type,type,typel); data+=typel; *data=0; data++;
	
	return b;
}
















