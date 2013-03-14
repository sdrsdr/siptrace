#include <stdlib.h>
#include "tagbulk.h"
#include <string.h>

tagbulkhead * tb_create() {
	tagbulkhead *tb=malloc(sizeof(tagbulkhead)+sizeof(tagelem)*TAGBULKSIZE);
	if (!tb) return NULL;
	tb->used=NULL;
	tb->free=(tagelem *)(tb+1);
	tb->free[TAGBULKSIZE-1].next=0;
	
	for (int x=0; x<TAGBULKSIZE-1; x++){
		tb->free[x].next=tb->free+(x+1);
	}
		 
	return tb;
}

tagelem* tb_expand(tagbulkhead * tb){
	tagelem * nb=malloc(sizeof(tagelem)*TAGBULKSIZE);
	for (int x=0; x<TAGBULKSIZE-1; x++){
		nb[x].next=nb+(x+1);
	}
	tb->free=nb;
	
	return nb;
	
}

tagelem * tb_getfree(tagbulkhead *tb){
	tagelem *fe;
	if (tb->free) {
		fe=tb->free;
	} else {
		fe=tb_expand(tb);
	}
	
	fe->next=tb->used;
	tb->used=fe;
	return fe;
}

int tb_findandfree(tagbulkhead *tb,char *tag,tl_int size){
	if (!tb->used) return 0;
	tagelem **prevup=&tb->used;
	tagelem *cu=tb->used;
	while (cu){
		if (size==cu->sz && memcmp(tag,cu->tag,size)==0){
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
int tb_findoradd(tagbulkhead *tb,char *tag,tl_int size){
	if (!tb->used) return 0;
	tagelem *cu=tb->used;
	while (cu){
		if (size==cu->sz && memcmp(tag,cu->tag,size)==0){
			return 1;
		}
		cu=cu->next;
	}
	cu=tb_getfree(tb);
	cu->sz=size;
	memcpy(cu->tag,tag,size);
	return 0;
}



















