//
// Created by khalegh on 6/5/22.
//

#ifndef LIMITER_RATE_LIMITER_H
#define LIMITER_RATE_LIMITER_H

#include <stddef.h>
#include <malloc.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#define  DROP_REQUEST           0
#define  ALLOW_REQUEST          1

int MAX_REQUEST_COUNT = 5; // maximum request per N second
int REQUEST_DIFF = 20; // check (time diff) every N second (above)
int BLOCKING_POLICY_TIME = 10; // attacker wait N second
int MAX_UNBLOCKING = 3;
int REVOKE_BLACK_LIST = 86400; // 24 hr

struct request_info {
    char *src_ip;
    int count;
    long time;
    long punishment_ttl; // if flood, then the ip will block for N second
    char *mac_address;
    int fooling_count;
    int is_live; // if not then revoke form link_list
    int is_zombie; // if flooding many times, then we assume this is a part of z_net 
    struct request_info *next;
};


struct request_info *queue_head = NULL;
struct request_info *queue_ptr = NULL;

struct request_info *req_registered(char *ip);

void iterate_req_src_queue();

long get_current_time() {
    struct timeval ts;
    gettimeofday(&ts, NULL); // return value can be ignored
    return ts.tv_sec;
}

int check_req_src_queue(char *src_ip) {
    struct request_info *pChain = req_registered(src_ip);
    if (pChain != NULL) {
        if (pChain->is_zombie == 1) {
            if (get_current_time() - pChain->time > REVOKE_BLACK_LIST) {
                pChain->count = 0;
                pChain->punishment_ttl = 0;
                pChain->is_zombie = 0;
                pChain->is_live = 1;
                pChain->fooling_count = 0;
                syslog(LOG_NOTICE, "{%s} revoked from black list", src_ip);
                return 0;
            }
            syslog(LOG_NOTICE, "zombie detected, {%s} blocked for {%d} sec.", src_ip, REVOKE_BLACK_LIST);
            return 1;
        }

        syslog(LOG_NOTICE, "{%s} already registered inside the hash list", src_ip);
        pChain->count++;
        long diff = get_current_time() - pChain->time;
        syslog(LOG_NOTICE, "time calculation -> {%ld}", diff);


        if (diff > REQUEST_DIFF) { // N sec
            if (pChain->count > MAX_REQUEST_COUNT) {
                if (pChain->punishment_ttl > BLOCKING_POLICY_TIME) { // punishment done, release client
                    if (pChain->fooling_count > MAX_UNBLOCKING) {
                        syslog(LOG_NOTICE, "there is no mercy, this is a part of z_net, {%s} moved in black list",
                               src_ip);
                        pChain->is_zombie = 1;
                        // todo khalegh :: redirect captcha page or any custom handshake :)
                    }
                    pChain->count = 0;
                    pChain->punishment_ttl = 0;
                    pChain->fooling_count++;
                    pChain->time = get_current_time();
                    syslog(LOG_NOTICE, "unblock {%s}.", src_ip);
                    return 0;
                } else { // punish
                    syslog(LOG_NOTICE, "flood by {%s} blocked!", src_ip);
                    pChain->punishment_ttl++;
                    return 1;
                }
            } else {
                syslog(LOG_NOTICE, "{%s} time & count reset.", src_ip);
                pChain->count = 0;
                pChain->punishment_ttl = 0;
                pChain->time = get_current_time();
            }
        }
    } else {
        struct request_info *node = (struct request_info *) malloc(sizeof(struct request_info));
        node->src_ip = src_ip;
        node->count = 0;
        node->punishment_ttl = 0;
        node->is_zombie = 0;
        node->is_live = 1;
        node->fooling_count = 0;

        struct timeval ts;
        gettimeofday(&ts, NULL); // return value can be ignored
        node->time = ts.tv_sec; // seconds

        node->next = queue_head;
        queue_head = node;
        syslog(LOG_NOTICE, "{%s} registered inside the hash list.", src_ip);
    }
    return 0;
}

void iterate_req_src_queue() {
    int count = 0;
    queue_ptr = queue_head;
    while (queue_ptr != NULL) {
        count++;
        syslog(LOG_NOTICE, "{%s} initialized ->[%ld],total req-> {%d}, flooding_count ->{%d} is_zombie-> {%d} ",
               queue_ptr->src_ip,
               queue_ptr->time,
               queue_ptr->count,
               queue_ptr->fooling_count,
               queue_ptr->is_zombie);

        queue_ptr = queue_ptr->next;
    }
    syslog(LOG_NOTICE, "total ip in list -> {%d}", count);

}

struct request_info *req_registered(char *ip) {
    queue_ptr = queue_head;
    while (queue_ptr != NULL) {
        int res = strcmp(queue_ptr->src_ip, ip);
        if (res == 0) {
            return queue_ptr;
        }
        queue_ptr = queue_ptr->next;
    }
    return NULL;
}


char *dump_ip(unsigned int ip, char *resp) {
    //todo validate ip value
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(resp, "%d.%d.%d.%d ", bytes[3], bytes[2], bytes[1], bytes[0]);
    return resp;
}

void remove_spaces(char *s) {
    char *d = s;
    do {
        while (*d == ' ') {
            ++d;
        }
    } while (*s++ = *d++);
}

#endif //LIMITER_RATE_LIMITER_H
