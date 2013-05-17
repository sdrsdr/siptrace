#include <stdlib.h>
#include "tagbulk.h"
#include <string.h>

#ifdef tbdebug
#include <stdio.h>
#endif

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
	tb->free=fe->next;
	fe->next=tb->used;
	tb->used=fe;
	return fe;
}

int tb_ttl_check(tagbulkhead *tb,time_t now){
	if (!tb->used) return 0;
	tagelem **prevup=&tb->used;
	tagelem *cu=tb->used;
	while (cu){
		if (cu->ttl<now){
			#ifdef tbdebug
			cu->tag[0]=0;
			#endif
			
			//store next
			tagelem *nextu=cu->next;
			
			//move cu to free
			*prevup=cu->next;
			cu->next=tb->free;
			tb->free=cu;
			
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

tagelem* tb_free (tagbulkhead *tb,tagelem *tagel, tagelem **prevp){
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
			return 1;
		}
		prevup=&(cu->next);
		cu=cu->next;
	}
	return 0;
}

int tb_find_and_set_ttl(tagbulkhead *tb,char *tag,tl_int size, time_t newttl){
	if (!tb->used) return 0;
	tagelem **prevup=&tb->used;
	tagelem *cu=tb->used;
	while (cu){
		if (size==cu->sz && memcmp(tag,cu->tag,size)==0){
			cu->ttl=newttl;
			return 1;
		}
		prevup=&(cu->next);
		cu=cu->next;
	}
	return 0;
}

int tb_find_or_add(tagbulkhead *tb,char *tag,tl_int size, time_t ttl){
	tagelem *cu;
	if (tb->used) {;
		cu=tb->used;
		while (cu){
			if (size==cu->sz && memcmp(tag,cu->tag,size)==0){
				cu->ttl=ttl;
				return 1;
			}
			cu=cu->next;
		}
	}
	cu=tb_get_free(tb);
	cu->sz=size;
	cu->ttl=ttl;
	memcpy(cu->tag,tag,size);
	return 0;
}


















