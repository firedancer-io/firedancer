#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include "wd_f1_mon.h"

static volatile int keepRunning = 1;

extern uint32_t            _wd_read_32             (wd_pci_t* pci, uint32_t addr);

typedef struct {

    uint64_t recv_cnt [2];
    uint64_t send_cnt;
    uint32_t running;
    uint32_t running_recv;
    uint32_t slot;

    wd_wksp_t wd;



} state_t;

state_t* _state_p;








double tiff(struct timespec t0, struct timespec t1)
{
    long seconds = t1.tv_sec - t0.tv_sec;
    long nanoseconds = t1.tv_nsec - t0.tv_nsec;
    return (double)seconds + (double)nanoseconds*1e-9;    
}

void print_counters(wd_wksp_t* wd)
{
    for (uint32_t i = 0; i < 16; i ++)
        wd_zprintf ("cnt[%2d] = %08x\n", i, wd_rd_cntr(wd, _state_p->slot, i));
}
void intHandler(int dummy) {
    (void)dummy;
    // _state_p->running_recv = 1;
    // for (int i = 0; i < 4096/4; i ++)
    //     printf ("DMA[%d]: %x\n", i, dma_buf[i]);
    // printf ("DMA: %x %x %x\n", dma_seq, dma_off, dma_buf[dma_off>>2]);
    // printf ("send_cnt: %lx, recv_cnt: %lx\n", _state_p->send_cnt, _state_p->recv_cnt[0]);
    printf ("\n");
    print_counters(&_state_p->wd);
    keepRunning = 0;

    _state_p->running = 0;

}



































char* ascii_chart[] = {
"                                                   +------------------------------------+",
"                                                   |             AWS-F1 x86             |",
"+-----------------------------------------+        |                                    |        +-----------------------------------------+",
"|               AWS-F1 FPGA               |        |                                    |        |                AWS-F1 FPGA              |",
"|                                         |        |                                    |        |                                         |",
"|    ---------        ---------           |        |          +=============+           |        |           ---------        ---------    |",
"|   |         |      |         |          |        |          |   Replay    |           |        |          |         |      |         |   |",
"|   |         <------| SHA-MOD |          |        |          |             |           |        |          | SHA-MOD |------>         |   |",
"|   |Scheduler|      |         |          |        |          +=============+           |        |          |         |      |Scheduler|   |",
"|   |         |       ----^----           |        |                 |                  |        |           ----^----       |         |   |",
"|   |         |           |               |        |                 |                  |        |               |           |         |   |",
"|    ---------            |               |        |                 v                  |        |               |            ---------    |",
"|        |            ----^----           |        |          +====== ======+           |        |           ----^----            |        |",
"|        |           |         |          -        -          |   Parser    |           -        -          |         |           |        |",
"|        |           | Extract <----------<--PCIe--<-----------             ------------>--PCIe-->----------> Extract |           |        |",
"|        |           |         |          -        -          +=============+           -        -          |         |           |        |",
"|        |            ---------           |        |                 |                  |        |           ---------            |        |",
"|    ----V----                            |        |                 v                  |        |                            ----V----    |",
"|   |         |                           |        |          +====== ======+           |        |                           |         |   |",
"|   |         |                           |        |          |  Sigverify  |           |        |                           |         |   |",
"|   |         |                           |        |          |             |           |        |                           |         |   |",
"|   |         |                           |        |          +=============+           |        |                           |         |   |",
"|   |  DS-DP  |                           |        |                 |                  |        |                           |  DS-DP  |   |",
"|   |         |       ---------           |        |                 v                  |        |           ---------       |         |   |",
"|   |         |      |         |          -        -          +====== ======+           -        -          |         |      |         |   |",
"|   |         |------> Reorder |---------->--PCIe-->---------->   Checker   <-----------<--PCIe--<----------| Reorder <------|         |   |",
"|   |         |      |         |          -        -          |             |           -        -          |         |      |         |   |",
"|    ---------        ---------           |        |          +=============+           |        |           ---------        ---------    |",
"|                                         |        |    checked                         |        |                                         |",
"|               Wiredancer                |        |    sig_ok                          |        |              Wiredancer                 |",
"+-----------------------------------------+        |    sig_err                         |        +-----------------------------------------+",
"                                                   |             Firedancer             |",
"                                                   +------------------------------------+",
"",
};

uint32_t cnt_data[][7] = {
    // line, col, cnt_type, cnt_color, print_width, hw_cnt_idx, pcie_slot
    {125-105, 71-5, 5, 0, 0, 256, 0}, // x86 rate
    {131-105, 71-5, 5, 0, 0, 258, 0}, // fpga rate
    {133-105, 70-5, 4, 0, 0, 260, 0}, // cnt checked
    {134-105, 70-5, 4, 0, 0, 261, 0}, // sig_pass
    {135-105, 70-5, 4, 0, 0, 262, 0}, // sig_fail
    {112-105, 71-5, 7, 0, 0, 263, 0}, // replay rate
    {119-105, 71-5, 5, 0, 0, 264, 0}, // parser rate

    {118-105,  34-1, 0, 0, 0,  10, 0}, // sw[0] to fpga-0
    {118-105, 101-1, 0, 0, 0,  10, 1}, // sw[0] to fpga-1
    {113-105,  24-1, 2, 0, 0,   0, 0}, // ext to sha_pre
    {113-105, 111-1, 2, 0, 0,   0, 1}, // ext to sha_pre
    {114-105,   7-1, 2, 0, 0,   2, 0}, // sha to sv0
    {114-105, 128-1, 2, 0, 0,   2, 1}, // sha to sv0
    {128-105,   7-1, 2, 0, 0,   3, 0}, // sv0 to sv1
    {128-105, 128-1, 2, 0, 0,   3, 1}, // sv0 to sv1
    {129-105,  34-1, 2, 0, 0,  13, 0}, // fpga-0 to sw[0]
    {129-105, 101-1, 2, 0, 0,  13, 1}, // fpga-0 to sw[0]
    {131-105,  33-1, 4, 0, 0,  13, 0}, // fpga-0 to sw[0]
    {131-105,  99-1, 4, 0, 0,  13, 1}, // fpga-0 to sw[0]
    {0, 0, 0, 0, 0, 0}, // end marker
};

void ascii_move_to(uint32_t from[2], uint32_t to[2])
{
    if (from[0] < to[0])
        printf ("\033[%dB", to[0]-from[0]);
    else
    if (from[0] > to[0])
        printf ("\033[%dA", from[0]-to[0]);
    if (from[1] < to[1])
        printf ("\033[%dC", to[1]-from[1]);
    else
    if (from[1] > to[1])
        printf ("\033[%dD", from[1]-to[1]);
}

void ascii_color(uint32_t col)
{
    switch(col)
    {
        case 0: printf ("\033[0m"); break;
        case 1: printf ("\033[32m"); break;
        case 2: printf ("\033[33m"); break;
        case 3: printf ("\033[31m"); break;
        case 4: printf ("\033[35m"); break;
    }
}

#define THOUSAND        (1000L)
#define MILLION         (1000L*1000L)
#define MILLION_F       (1000.0*1000.0)
#define TENMILLION      (1000L*1000L*10L)
#define BILLION         (1000L*1000L*1000L)
#define BILLION_F       (1000.0*1000.0*1000.0)
#define TENBILLION      (1000L*1000L*1000L*10L)
#define TRILLION        (1000L*1000L*1000L*1000L)

int pretty_num(char* st, uint64_t cnt, char* suffix)
{
    int sel = 0;
    if (cnt == 0)
    {
        sel = 0;
        sprintf(st, "<0> %s", suffix);
    }
    else if (cnt < THOUSAND)
    {
        sel = 0;
        sprintf(st, "%4lu%s", cnt, suffix);
    }
    else if (cnt < MILLION)
    {
        sel = 0;
        sprintf(st, "%3luK%s", cnt / (1000L), suffix);
    }
    else if (cnt < TENMILLION)
    {
        sel = 1;
        sprintf(st, "%1.1fM%s", ((double)cnt) / MILLION_F, suffix);
    }
    else if (cnt < BILLION)
    {
        sel = 2;
        sprintf(st, "%3luM%s", cnt / (MILLION), suffix);
    }
    else if (cnt < TENBILLION)
    {
        sel = 3;
        sprintf(st, "%1.1fG%s", ((double)cnt) / BILLION_F, suffix);
    }
    else
    {
        sel = 4;
        sprintf(st, "%3luG%s", cnt / BILLION, suffix);
    }
    return sel;
}

void* mon_thread(void* arg)
{
    // printf("mon_thread\n");


    uint32_t n_lines = 1000;
    uint64_t cnts[2][32];
    char cnt_st[32][512];
    uint32_t n_pcnt = 32;
    wd_mon_state_t* state = (wd_mon_state_t*)arg;

    uint64_t ts0 = 0;
    uint64_t ts1 = 0;

    memset(cnts, 0, sizeof(cnts));

    int first = 1;
    uint32_t from[2] = {n_lines, 0};
    uint32_t to[2] = {0, 0};
    // uint32_t millis = 200;
    uint32_t millis = 400;
    volatile uint32_t millis_inv = 1000 / millis;

    float ticks_per_ms = (float)get_tsc_ticks_ns()*(float)1e6;
    float rcp_ticks_per_ms = (float)1.0f/ticks_per_ms;
    long last_cycle = fd_tickcount();

    while (state->running && !state->running_recv)
    {
        // every 200ms
        usleep(1000*millis);
        if (!state->running)
            break;

        long current_cycle = fd_tickcount();
        long delta_cycle = current_cycle - last_cycle;
        last_cycle = current_cycle;
        uint32_t t_loop_ms = (uint32_t)(((float)delta_cycle) * rcp_ticks_per_ms);
        millis_inv = 32000 / t_loop_ms;

        if (!first)
        {
            to[0] = 0;
            to[1] = 0;
            ascii_move_to(from, to);
        }
        first = 0;

        // snapshot hw counters
        wd_snp_cntrs(&state->wd, 0);
        wd_snp_cntrs(&state->wd, 1);

        // read the counters
        for (int i = 0;; i ++)
        {
            if (cnt_data[i][0] == 0)
                break;
            uint64_t cnt = 0;
            if (cnt_data[i][5] < 100)
                cnt = wd_rd_cntr(&state->wd, cnt_data[i][6], (uint32_t)cnt_data[i][5]);
            if (cnt_data[i][5] ==256 )
                cnt = (uint)state->rate_x86;
            if (cnt_data[i][5] ==257 )
                cnt = (uint)state->cnt_x86;
            if (cnt_data[i][5] ==258 )
                cnt = (uint)state->rate__wd;
            if (cnt_data[i][5] ==259 )
                cnt = (uint)state->cnt__wd;
            if (cnt_data[i][5] ==260 )
                cnt = (uint)state->cnt_checked;
            if (cnt_data[i][5] ==261 )
                cnt = (uint)state->sig_pass;
            if (cnt_data[i][5] ==262 )
                cnt = (uint)state->sig_fail;
            if (cnt_data[i][5] ==263 )
                cnt = (uint)state->rate_replay;
            if (cnt_data[i][5] ==264 )
                cnt = (uint)state->rate_parser;
            cnts[1][i] = cnt;
        }

        // update deltas
        for (int i = 0;; i ++)
        {
            if (cnt_data[i][0] == 0)
                break;
            uint64_t cnt = 0;
            cnt = cnts[1][i];
            if (cnt < cnts[0][i])
                cnt += (1UL<<32);
            cnts[1][i] = cnt - cnts[0][i];
            cnts[0][i] = cnt & 0xFFFFFFFF;
        }

        for (int ci = 0;; ci ++)
        {
            if (cnt_data[ci][0] == 0)
                break;
            uint32_t color = 0;

            if (cnt_data[ci][2] == 0)
            {
                uint32_t cols[] = {3, 2, 1, 1, 1};
                uint64_t cnt = cnts[1][ci] * (512) * millis_inv;
                cnt /= 32;
                int sel = pretty_num(cnt_st[ci], cnt, "bps");
                color = cols[sel];
            }
            else if (cnt_data[ci][2] == 2)
            {
                uint32_t cols[] = {3, 1, 1, 1, 1};
                uint64_t cnt = cnts[1][ci] * millis_inv;
                cnt /= 32;
                int sel = pretty_num(cnt_st[ci], cnt, "Sps");
                color = cols[sel];
            }
            else if (cnt_data[ci][2] == 3)
            {
                uint32_t cols[] = {1, 3, 1, 1, 1};
                uint64_t cnt = cnts[0][ci];
                int sel = pretty_num(cnt_st[ci], cnt, "drp");
                color = cols[sel];
            }
            else if (cnt_data[ci][2] == 4)
            {
                uint64_t cnt = cnts[0][ci];
                sprintf(cnt_st[ci], "[%08lx]", cnt);
                color = 4;
            }
            else if (cnt_data[ci][2] == 5)
            {
                uint32_t cols[] = {3, 1, 1, 1, 1};
                uint64_t cnt = cnts[0][ci];
                int sel = pretty_num(cnt_st[ci], cnt, "Sps");
                color = cols[sel];
            }
            else if (cnt_data[ci][2] == 6)
            {
                uint32_t cols[] = {3, 2, 1, 1, 1};
                uint64_t cnt = cnts[0][ci] * 8; /* convert to bits per second */
                int sel = pretty_num(cnt_st[ci], cnt, "bps");
                color = cols[sel];
            }
            else if (cnt_data[ci][2] == 7)
            {
                uint32_t cols[] = {4, 4, 4, 4, 4}; /* basically a counter */
                uint64_t cnt = cnts[0][ci];
                int sel = pretty_num(cnt_st[ci], cnt, "Pps");
                color = cols[sel];
            }
            cnt_data[ci][3] = color;
            cnt_data[ci][4] = (uint32_t)strlen(cnt_st[ci]);
        }

        for (uint32_t li = 0; li < n_lines; li ++)
        {
            if (ascii_chart[li][0] == 0)
            {
                n_lines = li;
                from[0] = n_lines;// + n_pcnt + 1;
                (void)n_pcnt;
                break;
            }
            for (uint32_t ci = 0;; ci ++)
            {
                if (ascii_chart[li][ci] == 0)
                    break;

                int found = 0;
                for (int cnt_i = 0;; cnt_i ++)
                {
                    if (cnt_data[cnt_i][0] == 0)
                        break;
                    if (cnt_data[cnt_i][0] != li)
                        continue;
                    if (cnt_data[cnt_i][1] != ci)
                        continue;

                    found = 1;

                    ascii_color(cnt_data[cnt_i][3]);
                    printf ("%s", cnt_st[cnt_i]);
                    ascii_color(0);
                    ci += cnt_data[cnt_i][4] - 1;
                }

                if (!found)
                {
                    printf ("%c", ascii_chart[li][ci]);
                }
            }
            printf ("\n");
        }
        (void)ts0;
        (void)ts1;

        fflush(stdout);
    }
    return 0;
}


