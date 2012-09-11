#define ZMALLOC_C
#include "zmalloc.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <string.h>
#include "log.h"
#ifdef ZMALLOC

struct mbufferlist{
    char* filename;
    int stringno;
    RB_ENTRY(mbufferlist) links;
    TAILQ_HEAD(bufferstailhead, mbuffer) head;
};

struct mbuffer{
    char* filename;
    int stringno;
    void* pointer;
    size_t size;
    size_t rsize;
    RB_ENTRY(mbuffer) links;
    TAILQ_ENTRY(mbuffer) entries;
};

RB_HEAD (allocinfotreechunk, mbuffer) chunks = RB_INITIALIZER(&chunks);
RB_HEAD (allocinfotreelines, mbufferlist) byline = RB_INITIALIZER(&byline);

inline __attribute__((__gnu_inline__)) int ptrcmp(struct mbuffer* left, struct mbuffer* right){
    return left->pointer-right->pointer;
}
inline __attribute__((__gnu_inline__)) int linecmp(struct mbufferlist* left, struct mbufferlist* right){
    int c=left->filename-right->filename;
    if(c==0){
        c=left->stringno-right->stringno;
    }
    return c;
};
RB_GENERATE_STATIC( allocinfotreechunk, mbuffer, links, ptrcmp );
RB_GENERATE_STATIC( allocinfotreelines, mbufferlist, links, linecmp );

#define hoffset 32 
//#define toffset 32

void* zMalloc(size_t size, char* filename, int stringno,int c){
    struct mbuffer *b=malloc(sizeof(struct mbuffer)+1);
    if(!b){
        printf("Can't zMalloc at %s:%d\n",filename,stringno);
        exit(-1);
    }
    b->filename=filename;
    b->stringno=stringno;
    b->size=size;
#define ilen sizeof(long)
    int rlen=size+hoffset+ilen;
    if(rlen%64>0)rlen=((rlen/64)+1)*64;
    b->rsize=rlen;
    int toffset=rlen-(size+hoffset+ilen);
    //b->pointer=malloc(size+hoffset+toffset)+hoffset;
    b->pointer=malloc(rlen)+hoffset;
    if(!b->pointer){
        printf("Can't allocate memory %ld at %s:%d\n",size,filename,stringno);
        exit(-1);
    }
    /* Format
     *  -------------------------------------------------------------
     *  | header    32 bytes                    | buffer   | tail   |
     *  -------------------------------------------------------------
     *  | 0x3333 file string size 0x3535353535  | buffer   | 0x3535 |
     *     int    int  int   int   32byte-4xint |             
     */
    memset(b->pointer-hoffset,0x33,ilen);
    memset(b->pointer-hoffset+(ilen*4),0x34,hoffset-ilen*4);
    memset(b->pointer+size,0x35,toffset+1);
    //memset(b->pointer,0x00,size); //zero temp 4 test
    if(ilen==4){
        *((long*)(b->pointer-hoffset+ilen))=htobe32((long)filename);
        *((long*)(b->pointer-hoffset+(ilen*2)))=htobe32(stringno);
        *((long*)(b->pointer-hoffset+(ilen*3)))=htobe32(size);
    }else{
        *((long*)(b->pointer-hoffset+ilen))=htobe64((long)filename);
        *((long*)(b->pointer-hoffset+(ilen*2)))=htobe64(stringno);
        *((long*)(b->pointer-hoffset+(ilen*3)))=htobe64(size);
    }
    RB_INSERT(allocinfotreechunk, &chunks, b);
    struct mbufferlist *i,*l=malloc(sizeof(struct mbufferlist));
    l->filename=filename;
    l->stringno=stringno;
    i=RB_INSERT(allocinfotreelines, &byline, l);
    if(i==NULL){
        i=l;
        TAILQ_INIT(&l->head);
    }else{
        free(l);
    }
    TAILQ_INSERT_TAIL(&i->head, b, entries);
//    printf("%calloc(%ld -> %d) at %s:%d -> %p\n",(c?'c':'m'),size,rlen,filename,stringno,b->pointer);
	if(c)
	bzero(b->pointer,size);
    return b->pointer;
};

void zFree(void* ptr, char* filename, int stringno){
    struct mbuffer buf;
    buf.pointer=ptr;
    struct mbuffer *b;
    if((b=RB_FIND(allocinfotreechunk, &chunks, &buf))!=NULL){
//        printf("Free mem %p allocated at %s:%d\n",ptr,b->filename,b->stringno);

        struct mbufferlist *i,*l=malloc(sizeof(struct mbufferlist));
        l->filename=filename;
        l->stringno=stringno;
        i=RB_FIND(allocinfotreelines, &byline, l);
        free(l);
        TAILQ_REMOVE(&l->head,b,entries);

 
        RB_REMOVE(allocinfotreechunk, &chunks, b);
        free(b);
        free(ptr-hoffset);
    }else{
        printf("Can't free unallocated mem %p at %s:%d\n",ptr,filename,stringno);
        free(ptr-hoffset);
//	sleep(1);
    }
};

void* zCalloc(size_t number, size_t size, char* filename, int stringno){
	return zMalloc(number*size,filename,stringno,1);
};

char* zStrdup(char* ptr, char* filename, int stringno){
    int len=strlen(ptr);
    char* x=zMalloc(len+1,filename,stringno,0);
//    printf("Strdup at %s:%d %p\n",filename,stringno,ptr);
    memcpy(x,ptr,len);
    return x;
}


#endif
void dumpStat(void){
#ifdef ZMALLOC
/*
 * struct mbuffer *m=RB_MIN(allocinfotreechunk,&chunks);
    while((m=RB_NEXT(allocinfotreechunk,&chunks,m))!=NULL){
        printf("* %p %ld allocated at %s:%d\n",m->pointer,m->size,m->filename,m->stringno);
    }*/
    FILE *f;
    f=fopen("meminfo.txt","w");

    struct mbufferlist *m=RB_MIN(allocinfotreelines,&byline);
    while((m=RB_NEXT(allocinfotreelines,&byline,m))!=NULL){
        unsigned long bs=0;
        unsigned long bc=0;
        //printf("* alloc at %s:%d\n",m->filename,m->stringno);
        struct mbuffer *b;
        TAILQ_FOREACH(b,&m->head,entries){
            bs+=b->size;
            bc++;
//            printf("\t %p %ld\n",b->pointer,b->size);
        }
        printf("* alloc at %s:%d %ld times %ld bytes\n",m->filename,m->stringno,bc,bs);
        if(f)
        fprintf(f,"* alloc at %s:%d %ld times %ld bytes\n",m->filename,m->stringno,bc,bs);
    }
    if(f){
        fclose(f);
    }


    f=fopen("memdump.txt","w");
    m=RB_MIN(allocinfotreelines,&byline);
    while((m=RB_NEXT(allocinfotreelines,&byline,m))!=NULL){
        fprintf(f,"*** alloc at %s:%d file ptr %p\n",m->filename,m->stringno,m->filename);
        struct mbuffer *b;
        TAILQ_FOREACH(b,&m->head,entries){
            fprintf(f,"%12p - %12p %3d/%3d\t",b->pointer-hoffset,b->pointer-hoffset+b->rsize-1,(unsigned int)b->size,(unsigned int)b->rsize);
            fouthex(f,b->pointer-hoffset,hoffset,"%02x","%02x"); 
            if(*((char*)(b->pointer+b->size))==0x35){
            fprintf(f," \t   ");
            }else{
            fprintf(f," \t ##");
            }
            fouthex(f,b->pointer+b->size,b->rsize-b->size-hoffset,"%02x","%02x"); 
            fprintf(f,"\n\t%p\t",b->pointer);
            fouthex(f,b->pointer,b->size,"%02x","%02x"); 
            fprintf(f,"\n");
            //            printf("\t %p %ld\n",b->pointer,b->size);
        }
    }
    if(f){
        fclose(f);
    }
#endif
};
#ifdef ZMALLOC

#include <stdarg.h>

int zzvasprintf(char **strp, char* filename, int stringno, const char *fmt, va_list args) {
    int size;

    size = vsnprintf(NULL, 0, fmt, args);
    printf("size %d\n",size);
    if ((*strp = zMalloc(2+size + 1,filename,stringno,0)) == NULL) {
        return -1;
    }

    size = vsnprintf(*strp, size + 1, fmt, args);
    return size;
}

int zasprintf(char **strp, char* filename, int stringno, const char *fmt, ...) {
    va_list args;
    int size;

    va_start(args, fmt);
    size = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    //printf("size %d\n",size);
    char* ptr;
    if ((ptr = zMalloc(2+size + 1,filename,stringno,1)) == NULL) {
        return -1;
    }

    //printf("vsnprintf %d bytes to %p\n",size + 1,*strp);
    va_start(args, fmt);
    size = vsnprintf(ptr, size + 1, fmt, args);
    va_end(args);
    //  size = zzvasprintf(strp, filename, stringno, fmt, args);
    *strp=ptr;

//    printf("asprintf at %s:%d: '%s': '%s'\n",filename,stringno,fmt,*strp);
    return size;
}

#endif

