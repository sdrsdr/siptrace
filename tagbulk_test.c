#include "tagbulk.h"
#include <stdio.h>

#ifdef tbdebug
void tbdump(tagbulkhead *h){

	printf ("===== tbh@%p  (f:%p u:%p e:%d)=====\n",h,h->free,h->used,h->expands);
	for (int e=0; e<h->expands; e++){
		tagelem *bulk=h->bulks[e];
		printf (" ---- bulk%d@%p\n",e,bulk);		
		for (int be=0; be<TAGBULKSIZE; be++){
			tagelem *el=bulk+be;
			printf ("  be%d: %p n:%p t:%s\n",be, el,el->next,el->tag);
		}
	}
}
#else 
#define tbdump(p) 
#endif

int main(int argc, char *argv[]) {
	
	tagbulkhead *h;
	h=tb_create();
	
	printf("Init:\n");
	
	
	tb_findoradd(h,"test1",6);
	tb_findoradd(h,"test2",6);
	tb_findoradd(h,"test3",6);


	
	
	if (!tb_findandfree(h,"test2",6)){
		return 1;
	}
	
	if (tb_findandfree(h,"test2",6)){
		return 2;
	}

	tb_findoradd(h,"test4",6);
	
	
	if (!tb_findandfree(h,"test1",6)){
		return 3;
	}

	
	tb_findoradd(h,"test5",6);
	tb_findoradd(h,"test6",6);
	tb_findoradd(h,"test7",6);
	
	
	tb_findoradd(h,"test8",6);
	
	
	tb_findoradd(h,"test9",6);
	tb_findoradd(h,"test0",6);
	
	
	printf("t1 ...");
	if (!tb_findandfree(h,"test0",6)){
		printf("FAILED\n");
		return 4;
	}
	printf("done\n");
	
	printf("t2 ...");
	if (!tb_findandfree(h,"test4",6)){
		printf("FAILED\n");
		return 5;
	}
	printf("done\n");
	
	printf("t3 ...");
	if (!tb_findandfree(h,"test3",6)){
		printf("FAILED\n");
		return 6;
	}
	printf("done\n");
	
	printf("t4 ...");
	if (!tb_findandfree(h,"test9",6)){
		printf("FAILED\n");
		return 7;
	}
	printf("done\n");
	
	printf("t5 ...");
	if (!tb_findandfree(h,"test6",6)){
		printf("FAILED\n");
		return 8;
	}
	printf("done\n");
	
	printf("t6 ...");
	tb_findoradd(h,"testX",6);
	if (!tb_findandfree(h,"testX",6)){
		printf("FAILED\n");
		return 9;
	}
	printf("done\n");
	
	printf("Expands: %u\n",h->expands);
	return 0;
}
