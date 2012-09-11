#ifndef IPPOOL_H
#define IPPOOL_H

#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>

struct ip_entry {
    struct in_addr ip;
    struct usersession *sess;
    int allocated;
    int mark_for_remove;
    TAILQ_ENTRY(ip_entry) entries;
};


struct ippool {
    char* name;
    u_int32_t members;
    u_int32_t free;
    TAILQ_HEAD(pooltailhead, ip_entry) head;
    TAILQ_ENTRY(ippool) entries;
};

struct pools {
    TAILQ_HEAD(poolstailhead, ippool) head;
};

void pools_init(struct pools *pools);
struct ippool* pool_create(struct pools *pools,char *name);
struct ippool* get_pool(struct pools *pools,char *name);
int pool_add(struct ippool *pool, struct in_addr ip);
int pool_add_range(struct ippool *pool, struct in_addr first_ip, struct in_addr last_ip);
int pool_remove_range(struct ippool *pool, struct in_addr first_ip, struct in_addr last_ip);
struct ip_entry * allocate_ip(struct ippool *pool);
struct ip_entry * allocate_my_ip(struct ippool *pool,struct in_addr ip);
void deallocate(struct ippool *pool,struct ip_entry *ip);
#endif
