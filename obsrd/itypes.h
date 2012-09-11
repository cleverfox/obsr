#ifndef ITYPES_H
#define ITYPES_H
#include <sys/types.h>

typedef __uint8_t uint8;
typedef __uint16_t uint16;
typedef __uint32_t uint32;
typedef __uint64_t uint64;

#ifndef MIN
    #define MIN(a,b) (a>b)?b:a
#endif // MIN

#define int_caid  uint16
#define int_ident uint32
#define int_sid   uint16

#define IDENT_ANY 0x1de97ae7
#define SID_ANY   0x9e70
#define SID_ALL   0xfe80

#define MOD_UNKN        0
#define MOD_CLIENT      1
#define MOD_ACL         2
#define MOD_REQUEST     3
#define MOD_ROUTER      4
#define MOD_CACHE       5
#define MOD_BALANCER    6
#define MOD_UPSTREAM    7

#endif
