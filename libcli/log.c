#include "log.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "zmalloc.h"

void fouthex(FILE* ob,void* sstr,int length,char* pattern,char* lpattern){
    int c;
    if(sstr==NULL){
        fprintf(ob,"NULL");
    }else if(length<=0){
        fprintf(ob,"ZERO");
    }else{
        for(c=0;c<length;c++){
            unsigned char ch=*((unsigned char*)sstr+c);
            int r;
            if(ch<0x20){
                r=fprintf(ob,lpattern,ch);
            }else{
                r=fprintf(ob,pattern,ch);
            }
            if(r<=0){
                return;
            }
        }
    }
}

