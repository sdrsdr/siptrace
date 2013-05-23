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
typedef struct blob_t_ {
	time_t at;
	char *dev;
	char *srca;
	unsigned int srcp;
	int froml;
	char *from;
	char *fromtagstart;
	char *dsta;
	unsigned int dstp;
	int tol;
	char *to;
	char *type;
} blob_t;

typedef struct tagelem_ {
	struct tagelem_ *next;
	time_t ttl;
	tl_int  sz;
	char lastcode [3];
	char tag [MAXTAGSIZE];
	int printblob;
	blob_t *blob;
	int gotfinal;
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

int tb_find_or_add_ex(tagbulkhead *tb,char *tag,tl_int size, time_t ttl,tagelem **ret );
#define tb_find_or_add(tb,tag,size,ttl) tb_find_or_add_ex(tb,tag,size,ttl,NULL)

int tb_find_and_set_ttl_ex(tagbulkhead *tb,char *tag,tl_int size, time_t newttl,tagelem **ret );
#define tb_find_and_set_ttl(tb,tag,size,newttl) tb_find_and_set_ttl_ex(tb,tag,size,newttl,NULL )

void tb_ttl_check(tagbulkhead *tb,time_t now);


blob_t *mkblob(
	time_t at,char *dev, char *srca, unsigned int srcp,
	int froml,char *from,
	int fromtagstartl,char *fromtagstart,
	char *dsta, unsigned int dstp,
	int tol, char *to,
	int typel, char *type
);

#ifdef __cplusplus
//extern "C" {
}
#endif
#endif
