#ifndef HEADER_fd_src_wiredancer_wd_f1_h
#define HEADER_fd_src_wiredancer_wd_f1_h

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <immintrin.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <fpga_pci.h>
#pragma GCC diagnostic pop
#include <fpga_mgmt.h>
#include <utils/lcd.h>
#include <fpga_mgmt_internal.h>

#include "../../tango/mcache/fd_mcache.h"

#define WD_PCI_MAGIC            0xACE0FBAC
#define WD_N_PCI_SLOTS          8
#define WD_N_PCI_STREAMS        32

#define WD_TRY_LIMIT            1000000

typedef struct {

    uint64_t a; // address
    uint64_t b; // base
    uint64_t m; // mask

} wd_pci_st_t;

typedef struct {

    pci_bar_handle_t    bar0;
    pci_bar_handle_t    bar4;
    void*               bar4_addr;
    wd_pci_st_t         stream[WD_N_PCI_STREAMS];

} wd_pci_t;

typedef struct {

    uint32_t            req_slot;
    uint64_t            req_depth;

} wd_ed25519_verify_t;

typedef struct {

    int                 initialized;
    uint64_t            pci_slots;
    uint32_t            *stream_buf;
    wd_pci_t            pci[32];
    wd_ed25519_verify_t sv;
} wd_wksp_t;

int                     wd_init_pci     (wd_wksp_t* wd, uint64_t slots);
int                     wd_free_pci     (wd_wksp_t* wd);

void                    wd_rst_cntrs    (wd_wksp_t* wd, uint32_t slot);
void                    wd_snp_cntrs    (wd_wksp_t* wd, uint32_t slot);
uint32_t                wd_rd_cntr      (wd_wksp_t* wd, uint32_t slot, uint32_t ci);
uint64_t                wd_rd_ts        (wd_wksp_t* wd, uint32_t slot);

uint64_t                wd_get_phys     (void* p);
void                    wd_zprintf      (const char* format, ...);

/* wd_ed25519_verify_init_req initializes the internal state
   of the request path. */
void
wd_ed25519_verify_init_req( wd_wksp_t *        wd,
                            uint8_t            send_fails,
                            uint64_t           mcache_depth,
                            void*              mcache_addr);

/* wd_ed25519_verify_init_resp initializes the internal state
   of the response path. */
void
wd_ed25519_verify_init_resp( wd_wksp_t *       wd);


/* wd_ed25519_verify_req sends a verification request to the underlying
   hardware to verify the message according to the ED25519 standard.
   The function blocks until the request can be sent to the hardware.
   msg is assumed to point to the first byte of a sz byte memory region
   which holds the message to verify (sz==0 fine, msg==NULL fine if
   sz==0).
   sig is assumed to point to the first byte of a 64 byte memory region
   which holds the signature of the message.
   public_key is assumed to point to first byte of a 32-byte memory
   region that holds the public key to use to verify this message.
   Does no input argument checking.  This function takes a read 
   interest in msg, sig, public_key and private_key for the duration
   the call.
   ctrl shows start_of_packet and end_of_packet boundaries.
   ctrl[0] == sop
   ctrl[1] == eop
   Returns zero on success. */

int
wd_ed25519_verify_req( wd_wksp_t *   wd,
                       void const *  msg,
                       ulong         sz,
                       void const *  sig,
                       void const *  public_key,
                       uint64_t      m_seq,
                       uint32_t      m_chunk,
                       uint16_t      m_ctrl,
                       uint16_t      m_sz);

#endif
