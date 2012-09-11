#ifndef ZMALLOC_H
#define ZMALLOC_H
#include <sys/types.h>

void dumpStat(void);
#ifdef ZMALLOC

void* zMalloc(size_t size, char* filename, int stringno,int c);
void* zCalloc(size_t number, size_t size, char* filename, int stringno);
void* zRealloc(void* ptr, size_t size, char* filename, int stringno);
char* zStrdup(char* ptr, char* filename, int stringno);
void zFree(void* ptr, char* filename, int stringno);
int zasprintf(char **strp, char* filename, int stringno, const char *fmt, ...);


#define zmalloc(x) zMalloc(x,__FILE__,__LINE__,0)
#define zfree(x) zFree(x,__FILE__,__LINE__)
#define zrealloc(x,y) zRealloc(x,y,__FILE__,__LINE__)
#define zcalloc(x,y) zCalloc(x,y,__FILE__,__LINE__)
#ifndef ZMALLOC_C
#define strdup(x) zStrdup(x,__FILE__,__LINE__)
#define asprintf(x,...) zasprintf(x,__FILE__,__LINE__,__VA_ARGS__)
#endif
#else
#define zmalloc(x) malloc(x+sizeof(int))
#define zfree(x) free(x)
#define zrealloc(x,y) realloc(x,y)
#define zcalloc(x,y) calloc(x,y)
#endif



#if 0
#ifndef ZMALLOC_C
#define malloc(x) zMalloc(x,__FILE__,__LINE__,0)
#define free(x) zFree(x,__FILE__,__LINE__)
#define calloc(x,y) zCalloc(x,y,__FILE__,__LINE__)
#endif
#endif

#endif
