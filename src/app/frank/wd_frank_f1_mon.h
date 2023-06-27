#ifndef HEADER_fd_src_wiredancer_wd_f1_mon_h
#define HEADER_fd_src_wiredancer_wd_f1_mon_h

/* FIXME remove unnecessary ones */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/sha.h>

#include "../../wiredancer/c/wd_f1.h"
#include "wd_frank_f1_aux.h"

typedef struct {
    uint64_t recv_cnt [2];
    uint64_t send_cnt;
    uint64_t cnt_pkt_sz;
    uint64_t cnt_replay;
    uint64_t cnt_parser;
    uint64_t cnt_dedup;
    uint64_t cnt_sigv;
    uint64_t cnt_sw_sigv;
    uint64_t rate_pkt_sz;
    uint64_t rate_replay;
    uint64_t rate_parser;
    uint64_t rate_dedup;
    uint64_t rate_sigv;
    uint64_t rate_sw_sigv;
    uint32_t running;
    uint32_t running_recv;
    uint32_t stopped;
    uint32_t slot;
    wd_wksp_t wd;
} wd_mon_state_t;

void* mon_thread(void* arg);

#endif
