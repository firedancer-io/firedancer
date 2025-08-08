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

#include "wd_frank_f1_mon.h"





extern uint32_t _wd_read_32(wd_pci_t*, uint32_t a);



















































































char* ascii_chart[] = {
"+-----------------------------------------+                                                     +-----------------------------------------+",
"|               AWS-F1 FPGA(s)            |        +-----------------------------------+        |                AWS-F1 FPGA(s)           |",
"|                                         |        |             AWS-F1 x86(s)         |        |                                         |",
"|    ---------        ---------           |        |                                   |        |           ---------        ---------    |",
"|   |         |      |         |          |        |          +=============+          |        |          |         |      |         |   |",
"|   |         |      |         |          |        |          |    Replay   |          |        |          |         |      |         |   |",
"|   | ECC-CPU <------| SHA-MOD |          |        |          |             |          |        |          | SHA-MOD |------> ECC-CPU |   |",
"|   |         |      |         |          |        |          |             |          |        |          |         |      |         |   |",
"|   |         |      |         |          |        |          +=============+          |        |          |         |      |         |   |",
"|    ----v----        ----^----           |        |                 |                 |        |           ----^----        ----v----    |",
"|        |                |               |        |                 |                 |        |               |                |        |",
"|        |                |               |        |          +======v======+          |        |               |                |        |",
"|        |                |               |        |          |   Parser    |          |        |               |                |        |",
"|        |                |               |        |          |             |          |        |               |                |        |",
"|        |            ----^----           |        |          +=============+          |        |           ----^----            |        |",
"|        |           |         |          |        |                 |                 |        |          |         |           |        |",
"|        |           |         |          |        |                 |                 |        |          |         |           |        |",
"|        |           | Extract |          |        |          +======v======+          |        |          | Extract |           |        |",
"|    ----v----       |         |          |        |          |  Sigverify  |          |        |          |         |       ----v----    |",
"|   |         |      |         <----------<--PCIe--<-----------             ----------->--PCIe-->---------->         |      |         |   |",
"|   |         |       ---------           |        |          +=============+          |        |           ---------       |         |   |",
"|   |         |                           |        |           +-------------+         |        |                           |         |   |",
"|   |         |                           |        |            +-------------+        |        |                           |         |   |",
"|   |  DS-DP  |                           |        |                 |                 |        |                           |  DS-DP  |   |",
"|   |         |       ---------           |        |                 |                 |        |           ---------       |         |   |",
"|   |         |      |         |          |        |                 |                 |        |          |         |      |         |   |",
"|   |         |      |         |          -        -          +======v======+          -        -          |         |      |         |   |",
"|   |         |------> Reorder |---------->--PCIe-->---------->    Dedup    <----------<--PCIe--<----------| Reorder <------|         |   |",
"|   |         |      |         |          -        -          |             |          -        -          |         |      |         |   |",
"|   |         |      |         |          |        |          +=============+          |        |          |         |      |         |   |",
"|    ---------        ---------           |        |                                   |        |           ---------        ---------    |",
"|                                         |        |             Firedancer            |        |                                         |",
"|               Wiredancer                |        +-----------------------------------+        |              Wiredancer                 |",
"+-----------------------------------------+                                                     +-----------------------------------------+",
"", // end marker
};

uint32_t cnt_data[][7] = {
    // y, x, cnt_type, cnt_color, print_width, cnt_idx, pcie_slot

    {122-105,  34-1, 0, 0, 0,  10, 0}, // sw to fpga-L
    {123-105,  34-1, 0, 0, 0,  10, 2}, // sw to fpga-L
    {125-105,  34-1, 0, 0, 0,  10, 4}, // sw to fpga-L
    {126-105,  34-1, 0, 0, 0,  10, 6}, // sw to fpga-L

    {109-105,  24-1, 2, 0, 0,   0, 0}, // ext to sha_pre
    {110-105,  24-1, 2, 0, 0,   0, 2}, // ext to sha_pre
    {112-105,  24-1, 2, 0, 0,   0, 4}, // ext to sha_pre
    {113-105,  24-1, 2, 0, 0,   0, 6}, // ext to sha_pre

    {109-105,   7-1, 2, 0, 0,   2, 0}, // sha to sv0
    {110-105,   7-1, 2, 0, 0,   2, 2}, // sha to sv0
    {112-105,   7-1, 2, 0, 0,   2, 4}, // sha to sv0
    {113-105,   7-1, 2, 0, 0,   2, 6}, // sha to sv0

    {126-105,   7-1, 2, 0, 0,   3, 0}, // sv0 to sv1
    {127-105,   7-1, 2, 0, 0,   3, 2}, // sv0 to sv1
    {129-105,   7-1, 2, 0, 0,   3, 4}, // sv0 to sv1
    {130-105,   7-1, 2, 0, 0,   3, 6}, // sv0 to sv1

    {130-105,  34-1, 2, 0, 0,  13, 0}, // fpga-L to sw
    {131-105,  34-1, 2, 0, 0,  13, 2}, // fpga-L to sw
    {133-105,  34-1, 2, 0, 0,  13, 4}, // fpga-L to sw
    {134-105,  34-1, 2, 0, 0,  13, 6}, // fpga-L to sw

    {122-105,  99-1, 0, 0, 0,  10, 1}, // sw to fpga-R
    {123-105,  99-1, 0, 0, 0,  10, 3}, // sw to fpga-R
    {125-105,  99-1, 0, 0, 0,  10, 5}, // sw to fpga-R
    {126-105,  99-1, 0, 0, 0,  10, 7}, // sw to fpga-R

    {109-105, 110-1, 2, 0, 0,   0, 1}, // ext to sha_pre
    {110-105, 110-1, 2, 0, 0,   0, 3}, // ext to sha_pre
    {112-105, 110-1, 2, 0, 0,   0, 5}, // ext to sha_pre
    {113-105, 110-1, 2, 0, 0,   0, 7}, // ext to sha_pre

    {109-105, 127-1, 2, 0, 0,   2, 1}, // sha to sv0
    {110-105, 127-1, 2, 0, 0,   2, 3}, // sha to sv0
    {112-105, 127-1, 2, 0, 0,   2, 5}, // sha to sv0
    {113-105, 127-1, 2, 0, 0,   2, 7}, // sha to sv0

    {126-105, 127-1, 2, 0, 0,   3, 1}, // sv0 to sv1
    {127-105, 127-1, 2, 0, 0,   3, 3}, // sv0 to sv1
    {129-105, 127-1, 2, 0, 0,   3, 5}, // sv0 to sv1
    {130-105, 127-1, 2, 0, 0,   3, 7}, // sv0 to sv1

    {130-105,  99-1, 2, 0, 0,  13, 1}, // fpga-R to sw
    {131-105,  99-1, 2, 0, 0,  13, 3}, // fpga-R to sw
    {133-105,  99-1, 2, 0, 0,  13, 5}, // fpga-R to sw
    {134-105,  99-1, 2, 0, 0,  13, 7}, // fpga-R to sw

    {112-105,  67-1, 6, 0, 0, 100, 0}, // pkt_sz rate
    {111-105,  67-1, 5, 0, 0, 101, 0}, // replay rate
    {118-105,  67-1, 5, 0, 0, 102, 0}, // parser rate
    {133-105,  67-1, 5, 0, 0, 103, 0}, // dedup  rate
    {124-105,  67-1, 5, 0, 0, 104, 0}, // sigv   rate
    {999-105, 999-1, 5, 0, 0, 105, 0}, // sigv_swrate

    {120-105,  63-1, 7, 0, 0, 106, 0}, // txn_corrupt
    {120-105,  72-1, 8, 0, 0, 107, 0}, // txn_bcast
    {122-105,  64-1, 9, 0, 0, 108, 0}, // verify_live

    {0, 0, 0, 0, 0, 0}, // end marker
};

int anm_data[][9] = {
    // y-start
    //         x-start
    //                y-delta
    //                    x-delta
    //                        cnt
    //                           color
    //                              counter
    //                                  state
    //                                     anim char
    {114-105,  71-2,  1,  0,  3, 4, 40, 0, (int)'v'},
    {120-105,  71-2,  1,  0,  3, 4, 40, 0, (int)'v'},
    {128-105,  71-2,  1,  0,  4, 4, 45, 0, (int)'v'},

    {124-105,  64-2,  0, -1, 12, 4,  0, 0, (int)'<'},
    {124-105,  44-2,  0, -1, 12, 4,  0, 0, (int)'<'},
    {119-105,  28-2, -1,  0,  6, 4,  0, 0, (int)'^'},
    {111-105,  22-2,  0, -1,  7, 4,  0, 0, (int)'<'},
    {114-105,  11-2,  1,  0, 10, 4,  0, 0, (int)'v'},
    {132-105,  17-2,  0,  1,  7, 4,  0, 0, (int)'>'},
    {132-105,  33-2,  0,  1, 12, 4,  0, 0, (int)'>'},
    {132-105,  53-2,  0,  1, 12, 4,  0, 0, (int)'>'},

    {124-105,  78-2,  0,  1, 12, 4, 20, 0, (int)'>'},
    {124-105,  98-2,  0,  1, 12, 4, 20, 0, (int)'>'},
    {119-105, 114-2, -1,  0,  6, 4, 20, 0, (int)'^'},
    {111-105, 120-2,  0,  1,  7, 4, 20, 0, (int)'>'},
    {114-105, 131-2,  1,  0, 10, 4, 20, 0, (int)'v'},
    {132-105, 125-2,  0, -1,  7, 4, 20, 0, (int)'<'},
    {132-105,  89-2,  0, -1, 12, 4, 20, 0, (int)'<'},
    {132-105, 109-2,  0, -1, 12, 4, 20, 0, (int)'<'},

    {0, 0, 0, 0, 0, 0, 0}, // end marker
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

int ascii_color(char* out, uint32_t col)
{
    switch(col)
    {
        case 0: return sprintf (out, "\033[0m");  // white
        case 1: return sprintf (out, "\033[32m"); // green
        case 2: return sprintf (out, "\033[33m"); // yellow
        case 3: return sprintf (out, "\033[31m"); // red
        case 4: return sprintf (out, "\033[35m"); // purple
        case 5: return sprintf (out, "\033[36m"); // cyan
    }
    return 0;
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
        sprintf(st, "   . ");
    }
    else if (cnt < THOUSAND)
    {
        sel = 1;
        sprintf(st, "%4lu%s", cnt, suffix);
    }
    else if (cnt < MILLION)
    {
        sel = 2;
        sprintf(st, "%3luK%s", cnt / (1000L), suffix);
    }
    else if (cnt < 2*MILLION)
    {
        sel = 3;
        sprintf(st, "%1.2fM%s", ((double)cnt) / MILLION_F, suffix);
    }
    else if (cnt < TENMILLION)
    {
        sel = 3;
        sprintf(st, "%1.1fM%s", ((double)cnt) / MILLION_F, suffix);
    }
    else if (cnt < BILLION)
    {
        sel = 4;
        sprintf(st, "%3luM%s", cnt / (MILLION), suffix);
    }
    else if (cnt < TENBILLION)
    {
        sel = 5;
        sprintf(st, "%1.1fG%s", ((double)cnt) / BILLION_F, suffix);
    }
    else
    {
        sel = 6;
        sprintf(st, "%3luG%s", cnt / BILLION, suffix);
    }
    return sel;
}

#define MAX_LINES 128
#define MAX_LINE_WIDTH 512

void* mon_thread(void* arg)
{
    uint64_t cnts[2][64];
    char cnt_st[64][512];
    wd_mon_state_t* state = (wd_mon_state_t*)arg;

    memset(cnts, 0, sizeof(cnts));

    char buffer_prev[MAX_LINES][MAX_LINE_WIDTH] = {0};
    char buffer_curr[MAX_LINES][MAX_LINE_WIDTH] = {0};

    int first = 1;
    uint32_t from[2] = {0, 0};
    uint32_t to[2] = {0, 0};
    uint32_t millis = 100;
    volatile uint32_t millis_inv = 1000 / millis;

    float ticks_per_ms = (float)get_tsc_ticks_ns()*(float)1e6;
    float rcp_ticks_per_ms = (float)1.0f/ticks_per_ms;
    long last_cycle = fd_tickcount();

    while (state->running)
    {
        usleep(1000*millis);
        if (!state->running)
            break;

        if (!first)
            ascii_move_to(from, to);

        /* switch to alternate buffer, clear, hide cursor */
        if (first) {
            printf("\033[?1049h\033[2J\033[?25l");
        }
        
        from[0] = 0;

        long current_cycle = fd_tickcount();
        long delta_cycle = current_cycle - last_cycle;
        last_cycle = current_cycle;
        uint32_t t_loop_ms = (uint32_t)(((float)delta_cycle) * rcp_ticks_per_ms);
        // postpone division by 32 to keep precision
        millis_inv = 32000 / t_loop_ms;

        // snapshot hw counters of all slots
        // this is a noop for slots we don't own
        for (uint32_t si = 0; si < WD_N_PCI_SLOTS; si ++)
            wd_snp_cntrs(&state->wd, si);

        // read counters
        for (int i = 0;; i ++)
        {
            if (cnt_data[i][0] == 0)
                break;
            uint64_t cnt = 0;
            if (cnt_data[i][5] < 100)
                cnt = wd_rd_cntr(&state->wd, cnt_data[i][6], (uint32_t)cnt_data[i][5]);
            if (cnt_data[i][5] == 100 )
                cnt = (uint)state->rate_pkt_sz;
            if (cnt_data[i][5] == 101 )
                cnt = (uint)state->rate_replay;
            if (cnt_data[i][5] == 102 )
                cnt = (uint)state->rate_parser;
            if (cnt_data[i][5] == 103 )
                cnt = (uint)state->rate_dedup;
            if (cnt_data[i][5] == 104 )
                cnt = (uint)state->rate_sigv;
            if (cnt_data[i][5] == 105 )
                cnt = (uint)state->rate_sw_sigv;
            if (cnt_data[i][5] == 106 )
                cnt = (uint)state->txn_corrupt;
            if (cnt_data[i][5] == 107 )
                cnt = (uint)state->txn_bcast;
            if (cnt_data[i][5] == 108 )
                cnt = (uint)state->verify_live;
            cnts[1][i] = cnt;
            if (first)
                cnts[0][i] = cnt;
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

        first = 0;

        for (int ci = 0;; ci ++)
        {
            if (cnt_data[ci][0] == 0)
                break;
            uint32_t color = 0;

            if (cnt_data[ci][2] == 0)
            {
                uint32_t cols[] = {1, 1, 5, 1, 1, 1, 1};
                uint64_t cnt = cnts[1][ci] * (512) * millis_inv;
                cnt /= 32;
                int sel = pretty_num(cnt_st[ci], cnt, "bps");
                color = cols[sel];
            }
            else if (cnt_data[ci][2] == 2)
            {
                uint32_t cols[] = {1, 1, 5, 1, 1, 1, 1};
                uint64_t cnt = cnts[1][ci] * millis_inv;
                cnt /= 32;
                int sel = pretty_num(cnt_st[ci], cnt, "Sps");
                color = cols[sel];
            }
            else if (cnt_data[ci][2] == 3)
            {
                uint32_t cols[] = {1, 1, 5, 1, 1, 1, 1};
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
                uint32_t cols[] = {1, 1, 5, 1, 1, 1, 1};
                uint64_t cnt = cnts[0][ci];
                int sel = pretty_num(cnt_st[ci], cnt, "Sps");
                color = cols[sel];
                cnts[1][ci] = cnts[0][ci];
            }
            else if (cnt_data[ci][2] == 6)
            {
                uint32_t cols[] = {1, 1, 5, 1, 1, 1, 1};
                uint64_t cnt = cnts[0][ci] * 8;
                int sel = pretty_num(cnt_st[ci], cnt, "bps");
                color = cols[sel];
                cnts[1][ci] = cnt;
            }
            else if (cnt_data[ci][2] == 7)
            {
                uint64_t cnt = cnts[0][ci];
                sprintf(cnt_st[ci], "%s", cnt ? "corrupt" : " ");
                color = 2;
            }
            else if (cnt_data[ci][2] == 8)
            {
                uint64_t cnt = cnts[0][ci];
                sprintf(cnt_st[ci], "%s", cnt ? "bcast" : " ");
                color = 2;
            }
            else if (cnt_data[ci][2] == 9)
            {
                uint64_t cnt = cnts[0][ci];
                sprintf(cnt_st[ci], "%02lu", cnt);
                color = 2;
            }
            cnt_data[ci][3] = color;
            cnt_data[ci][4] = (uint32_t)strlen(cnt_st[ci]);
        }

        // draw ascii art
        for (uint32_t li = 0; li < MAX_LINES; li ++)
        {
            if (ascii_chart[li][0] == 0)
                break;
            char* out_st = buffer_curr[li];
            int out_pos = 0;
            for (uint32_t ci = 0;; ci ++)
            {
                if (ascii_chart[li][ci] == 0)
                    break;

                int found = 0;

                // find a matching counter
                for (int cnt_i = 0;; cnt_i ++)
                {
                    if (cnt_data[cnt_i][0] == 0)
                        break;
                    if (cnt_data[cnt_i][0] != li)
                        continue;
                    if (cnt_data[cnt_i][1] != ci)
                        continue;

                    found = 1;

                    out_pos += ascii_color(out_st+out_pos, cnt_data[cnt_i][3]);
                    out_pos += sprintf (out_st+out_pos, "%s", cnt_st[cnt_i]);
                    ci += cnt_data[cnt_i][4] - 1;
                }

                // find a matching animation
                if (!found)
                {
                    for (int anm_i = 0;; anm_i ++)
                    {
                        if (anm_data[anm_i][0] == 0)
                            break;
                        if (1
                            && (anm_data[anm_i][0] + (anm_data[anm_i][2] * anm_data[anm_i][7]) == (int)li)
                            && (anm_data[anm_i][1] + (anm_data[anm_i][3] * anm_data[anm_i][7]) == (int)ci)
                            && (cnts[1][anm_data[anm_i][6]] != 0)
                        )
                        {
                            out_pos += ascii_color(out_st+out_pos, (uint32_t)anm_data[anm_i][5]);
                            out_pos += sprintf (out_st+out_pos, "%c", anm_data[anm_i][8]);
                            found = 1;
                            break;
                        }
                    }
                }

                if (!found)
                    out_pos += sprintf (out_st+out_pos, "%c", ascii_chart[li][ci]);
                else
                    out_pos += ascii_color(out_st+out_pos, 0);
            }
            out_st[out_pos] = '\0';
            /* only print changed lines – clear to EOL first */
            if (strcmp(buffer_prev[li], buffer_curr[li]) != 0)
            {
                printf("\033[%d;1H\033[K%s", li + 1, buffer_curr[li]);
                strcpy(buffer_prev[li], buffer_curr[li]);
            }
        }

        // update animation states
        for (int anm_i = 0;; anm_i ++)
        {
            if (anm_data[anm_i][0] == 0)
                break;
            anm_data[anm_i][7] ++;
            if (anm_data[anm_i][7] == anm_data[anm_i][4])
                anm_data[anm_i][7] = 0;
        }
        if (0)
        for (uint32_t i = 0; i < 20; i ++)
        {
            wd_zprintf ("cnt[%02u] =", i);
            for (uint32_t si = 0; si < 8; si ++)
            {
                wd_zprintf (" %08x", wd_rd_cntr(&state->wd, si, i));
            }
            printf ("\n");
            from[0] ++;
        }
        fflush(stdout);
    }
    state->stopped = 1;

    /* show cursor, restore normal screen buffer */
    printf("\033[?25h\033[?1049l");

    return 0;
}
