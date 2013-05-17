#ifndef siptrace_tagbulk_h
#define siptrace_tagbulk_h


#define no_tbdebug

#include <time.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAXTAGSIZE 50
#define TAGBULKSIZE 5
	
#ifdef tbdebug
#define DBG_MAX_EXPANDS 5
#endif
	
#define tl_int uint16_t
	
typedef struct tagelem_ {
	struct tagelem_ *next;
	time_t ttl;
	tl_int  sz;
	char tag [MAXTAGSIZE];
} tagelem;

typedef struct tagbulkhead_ {
	tagelem * free;
	tagelem * used;
	time_t last_ttl_check;
	int expands;
#ifdef tbdebug
	tagelem * bulks[DBG_MAX_EXPANDS];
#endif

} tagbulkhead;

tagbulkhead * tb_create();
tagelem * tb_getfree(tagbulkhead *tb);

tagelem * tb_find (tagbulkhead *tb,char *tag,tl_int size, tagelem ***prevp);

int tb_find_and_free(tagbulkhead* tb, char* tag, uint16_t size);
int tb_find_and_set_ttl(tagbulkhead* tb, char* tag, uint16_t size,time_t ttl);
int tb_find_or_add(tagbulkhead *tb,char *tag,tl_int size, time_t ttl);
int tb_ttl_check(tagbulkhead *tb,time_t now);
int tb_find_and_set_ttl(tagbulkhead *tb,char *tag,tl_int size, time_t newttl);

#ifdef __cplusplus
//extern "C" {
}
#endif
#endif
