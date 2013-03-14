#ifndef siptrace_tagbulk_h
#define siptrace_tagbulk_h

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAXTAGSIZE 50
#define TAGBULKSIZE 50

#define tl_int uint16_t
	
typedef struct tagelem_ {
	struct tagelem_ *next;
	tl_int  sz;
	char tag [MAXTAGSIZE];
} tagelem;

typedef struct tagbulkhead_ {
	tagelem * free;
	tagelem * used;
} tagbulkhead;

tagbulkhead * tb_create();
tagelem * tb_getfree(tagbulkhead *tb);

int tb_findandfree(tagbulkhead* tb, char* tag, uint16_t size);
int tb_findoradd(tagbulkhead *tb,char *tag,tl_int size);

#ifdef __cplusplus
//extern "C" {
}
#endif
#endif
