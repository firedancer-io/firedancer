#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "wd_f1.h"

// private functions
uint32_t            _wd_read_32             (wd_pci_t* pci, uint32_t addr);
void                _wd_write_32            (wd_pci_t* pci, uint32_t addr, uint32_t v);
void                _wd_write_256           (wd_pci_t* pci, uint64_t off, void const* buf);
inline void         _wd_stream_256          (wd_wksp_t* wd, uint32_t slot, void const* buf);
void                _wd_stream_flush        (wd_wksp_t* wd, uint32_t slot);
uint32_t            _wd_next_slot           (wd_wksp_t* wd, uint32_t slot);

// PPPPPPPPPPPPPPPPP           CCCCCCCCCCCCCIIIIIIIIII
// P::::::::::::::::P       CCC::::::::::::CI::::::::I
// P::::::PPPPPP:::::P    CC:::::::::::::::CI::::::::I
// PP:::::P     P:::::P  C:::::CCCCCCCC::::CII::::::II
//   P::::P     P:::::P C:::::C       CCCCCC  I::::I  
//   P::::P     P:::::PC:::::C                I::::I  
//   P::::PPPPPP:::::P C:::::C                I::::I  
//   P:::::::::::::PP  C:::::C                I::::I  
//   P::::PPPPPPPPP    C:::::C                I::::I  
//   P::::P            C:::::C                I::::I  
//   P::::P            C:::::C                I::::I  
//   P::::P             C:::::C       CCCCCC  I::::I  
// PP::::::PP            C:::::CCCCCCCC::::CII::::::II
// P::::::::P             CC:::::::::::::::CI::::::::I
// P::::::::P               CCC::::::::::::CI::::::::I
// PPPPPPPPPP                  CCCCCCCCCCCCCIIIIIIIIII

int wd_init_pci(wd_wksp_t* wd, uint64_t slots)
{
    wd->pci_slots = slots;
    wd->stream_buf = mmap(0, 32, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);

    fpga_mgmt_state.initialized = true;

    for (uint32_t slot = 0; slot < WD_N_PCI_SLOTS; slot ++)
    {
        wd_pci_t* pci = &wd->pci[slot];

        pci->bar0 = PCI_BAR_HANDLE_INIT;
        pci->bar4 = PCI_BAR_HANDLE_INIT;
        pci->bar4_addr = 0;

        fpga_mgmt_state.slots[slot].handle = PCI_BAR_HANDLE_INIT;

        if ((wd->pci_slots & (1UL<<slot)) == 0)
            continue;

        int rc;

        rc = fpga_pci_attach((int)slot, FPGA_APP_PF, APP_PF_BAR0, 0, &pci->bar0);
        if (rc)
        {
            FD_LOG_ERR(( "Unable to attach to the AFI on slot id %d", slot ));
            return -1;
        }
        rc = fpga_pci_attach((int)slot, FPGA_APP_PF, APP_PF_BAR4, BURST_CAPABLE, &pci->bar4);
        if (rc)
        {
            FD_LOG_ERR (( "Unable to attach to the AFI on slot id %d", slot ));
            return -1;
        }

        fpga_pci_get_address(pci->bar4, 0, 1024*1024, (void**)&pci->bar4_addr);

        for (uint32_t si = 0; si < WD_N_PCI_STREAMS; si ++)
        {
            pci->stream[si].a = 0x0;
            pci->stream[si].b = 1+si;
            pci->stream[si].b <<= 32;
            pci->stream[si].m = (1L << 20);
        }
    }

    return 0;
}

int wd_free_pci (wd_wksp_t* wd)
{
    (void)wd;
    return 0;
}

uint32_t _wd_read_32(wd_pci_t* pci, uint32_t addr)
{
    int rc;
    uint32_t value;
    rc = fpga_pci_peek(pci->bar0, addr, &value);
    if (rc)
        FD_LOG_ERR (("Unable to read from the fpga !" ));
    return value;
}

void _wd_write_32(wd_pci_t* pci, uint32_t addr, uint32_t v)
{
    fpga_pci_poke(pci->bar0, addr, v);
}

void _wd_write_256(wd_pci_t* pci, uint64_t off, void const* buf)
{
    uint32_t* data = (uint32_t*)buf;
    volatile uint32_t* addr = (volatile uint32_t*)pci->bar4_addr;
    addr += (off >> 2);
    if (0)
    {
        addr[0] = data[0];
        addr[1] = data[1];
        addr[2] = data[2];
        addr[3] = data[3];
        addr[4] = data[4];
        addr[5] = data[5];
        addr[6] = data[6];
        addr[7] = data[7];
    } else
    {
        __m256i v;
        v = _mm256_load_si256((__m256i*)data);
        _mm256_stream_si256((__m256i*)(addr), v);
    }
}

inline void _wd_stream_256(wd_wksp_t* wd, uint32_t slot, void const* buf)
{
    wd_pci_st_t* pci_st = &wd->pci[slot].stream[0];
    _wd_write_256(&wd->pci[slot], pci_st->a | pci_st->b, buf);
    pci_st->a += 32;
    if (pci_st->a == pci_st->m)
    {
        _wd_stream_flush(wd, slot);
        pci_st->a = 0;
    }
    else if ((pci_st->a & 0xFC0) == 0xFC0)
    {
        _wd_stream_flush(wd, slot);
    }
}

void _wd_stream_flush(wd_wksp_t* wd, uint32_t slot)
{
    (void)wd;
    (void)slot;
    _mm_sfence();
}

// MMMMMMMM               MMMMMMMMIIIIIIIIII   SSSSSSSSSSSSSSS         CCCCCCCCCCCCC
// M:::::::M             M:::::::MI::::::::I SS:::::::::::::::S     CCC::::::::::::C
// M::::::::M           M::::::::MI::::::::IS:::::SSSSSS::::::S   CC:::::::::::::::C
// M:::::::::M         M:::::::::MII::::::IIS:::::S     SSSSSSS  C:::::CCCCCCCC::::C
// M::::::::::M       M::::::::::M  I::::I  S:::::S             C:::::C       CCCCCC
// M:::::::::::M     M:::::::::::M  I::::I  S:::::S            C:::::C              
// M:::::::M::::M   M::::M:::::::M  I::::I   S::::SSSS         C:::::C              
// M::::::M M::::M M::::M M::::::M  I::::I    SS::::::SSSSS    C:::::C              
// M::::::M  M::::M::::M  M::::::M  I::::I      SSS::::::::SS  C:::::C              
// M::::::M   M:::::::M   M::::::M  I::::I         SSSSSS::::S C:::::C              
// M::::::M    M:::::M    M::::::M  I::::I              S:::::SC:::::C              
// M::::::M     MMMMM     M::::::M  I::::I              S:::::S C:::::C       CCCCCC
// M::::::M               M::::::MII::::::IISSSSSSS     S:::::S  C:::::CCCCCCCC::::C
// M::::::M               M::::::MI::::::::IS::::::SSSSSS:::::S   CC:::::::::::::::C
// M::::::M               M::::::MI::::::::IS:::::::::::::::SS      CCC::::::::::::C
// MMMMMMMM               MMMMMMMMIIIIIIIIII SSSSSSSSSSSSSSS           CCCCCCCCCCCCC

void wd_rst_cntrs(wd_wksp_t* wd, uint32_t slot)
{
    if (!(wd->pci_slots & (1UL << slot)))
        return;
    _wd_write_32(&wd->pci[slot], 0x20<<2, 1);
}
void wd_snp_cntrs(wd_wksp_t* wd, uint32_t slot)
{
    if (!(wd->pci_slots & (1UL << slot)))
        return;
    _wd_write_32(&wd->pci[slot], 0x20<<2, 2);
}
uint32_t wd_rd_cntr(wd_wksp_t* wd, uint32_t slot, uint32_t ci)
{
    if (!(wd->pci_slots & (1UL << slot)))
        return 0;
    _wd_write_32(&wd->pci[slot], 0x10<<2, ci);
    return _wd_read_32(&wd->pci[slot], 0x20<<2);
}

uint64_t wd_rd_ts(wd_wksp_t* wd, uint32_t slot)
{
    if (!(wd->pci_slots & (1UL << slot)))
        return 0;
    uint64_t ts = _wd_read_32(&wd->pci[slot], (0x12+0)<<2);
    ts <<= 32;
    ts |= _wd_read_32(&wd->pci[slot], (0x11+0)<<2);
    return ts;
}

void wd_zprintf(const char* format, ...)
{
    char s[512];
    va_list argptr;
    va_start(argptr, format);
    vsnprintf (s, 512, format, argptr);
    for (int i = 0; s[i]; i ++) if (s[i] == '0') s[i] = '_';
    printf ("%s", s);
    va_end(argptr);
}

uint32_t _wd_next_slot(wd_wksp_t* wd, uint32_t slot)
{
    for (int i = 0; i < WD_N_PCI_SLOTS; i ++)
    {
        slot ++;
        if (slot >= WD_N_PCI_SLOTS)
            slot = 0;
        if (wd->pci_slots & (1UL << slot))
            break;
    }
    return slot;
}

int _wd_set_vdip_64(wd_wksp_t* wd, uint32_t slot, uint32_t vi, uint64_t v)
{
    (void)wd;
    for (uint32_t i = 0; i < 8; i ++)
    {
        uint32_t vdip = 0xf;
        vdip |= ((vi * 8) + i) << 4;
        vdip |= (uint32_t)((v & 0xff) << 8);
        v >>= 8;
        if (fpga_mgmt_set_vDIP((int)slot, (uint16_t)vdip))
        {
            FD_LOG_ERR (( "Unable to set privileged bytes for slot id %d", slot ));
            return -1;
        }
    }
    return 0;
}


// DDDDDDDDDDDDD        MMMMMMMM               MMMMMMMM               AAA               
// D::::::::::::DDD     M:::::::M             M:::::::M              A:::A              
// D:::::::::::::::DD   M::::::::M           M::::::::M             A:::::A             
// DDD:::::DDDDD:::::D  M:::::::::M         M:::::::::M            A:::::::A            
//   D:::::D    D:::::D M::::::::::M       M::::::::::M           A:::::::::A           
//   D:::::D     D:::::DM:::::::::::M     M:::::::::::M          A:::::A:::::A          
//   D:::::D     D:::::DM:::::::M::::M   M::::M:::::::M         A:::::A A:::::A         
//   D:::::D     D:::::DM::::::M M::::M M::::M M::::::M        A:::::A   A:::::A        
//   D:::::D     D:::::DM::::::M  M::::M::::M  M::::::M       A:::::A     A:::::A       
//   D:::::D     D:::::DM::::::M   M:::::::M   M::::::M      A:::::AAAAAAAAA:::::A      
//   D:::::D     D:::::DM::::::M    M:::::M    M::::::M     A:::::::::::::::::::::A     
//   D:::::D    D:::::D M::::::M     MMMMM     M::::::M    A:::::AAAAAAAAAAAAA:::::A    
// DDD:::::DDDDD:::::D  M::::::M               M::::::M   A:::::A             A:::::A   
// D:::::::::::::::DD   M::::::M               M::::::M  A:::::A               A:::::A  
// D::::::::::::DDD     M::::::M               M::::::M A:::::A                 A:::::A 
// DDDDDDDDDDDDD        MMMMMMMM               MMMMMMMMAAAAAAA                   AAAAAAA

uint64_t _wd_get_phys(void* p)
{
    uint64_t PAGE_SIZE = (uint64_t)sysconf(_SC_PAGESIZE);
    int pagemap_fd;
    uint64_t vaddr;
    uintptr_t vpn;
    uint64_t pfn;

    pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0)
    {
        FD_LOG_ERR (( "cannot open pagemap file: %d ", pagemap_fd ));
        return 0;
    }

    vaddr = (uint64_t)p;
    vpn = vaddr / PAGE_SIZE;
    for (size_t nread = 0; nread < sizeof(pfn); )
    {
        ssize_t ret = pread(pagemap_fd, &pfn, sizeof(pfn) - nread, (off_t)((vpn * sizeof(pfn)) + nread));
        if (ret <= 0)
        {
            FD_LOG_ERR (( "pread error: %lu ", ret ));
            close(pagemap_fd);
            return 0;
        }
        nread += (size_t)ret;
    }
    pfn &= (1UL << 55) - 1;
    pfn = (pfn * (long unsigned int)PAGE_SIZE) + (vaddr % (long unsigned int)PAGE_SIZE);

    close(pagemap_fd);

    return pfn;
}

//    SSSSSSSSSSSSSSS VVVVVVVV           VVVVVVVV
//  SS:::::::::::::::SV::::::V           V::::::V
// S:::::SSSSSS::::::SV::::::V           V::::::V
// S:::::S     SSSSSSSV::::::V           V::::::V
// S:::::S             V:::::V           V:::::V 
// S:::::S              V:::::V         V:::::V  
//  S::::SSSS            V:::::V       V:::::V   
//   SS::::::SSSSS        V:::::V     V:::::V    
//     SSS::::::::SS       V:::::V   V:::::V     
//        SSSSSS::::S       V:::::V V:::::V      
//             S:::::S       V:::::V:::::V       
//             S:::::S        V:::::::::V        
// SSSSSSS     S:::::S         V:::::::V         
// S::::::SSSSSS:::::S          V:::::V          
// S:::::::::::::::SS            V:::V           
//  SSSSSSSSSSSSSSS               VVV            

void
wd_ed25519_verify_init_req( wd_wksp_t *        wd,
                            uint8_t            send_fails,
                            uint64_t           mcache_depth,
                            void*              mcache_addr)
{
    wd->sv.req_slot     = _wd_next_slot(wd, 0);
    wd->sv.req_depth    = mcache_depth;
    uint64_t dma_phys   = _wd_get_phys(mcache_addr);

    for (uint32_t slot = 0; slot < WD_N_PCI_SLOTS; slot ++)
    {
        if (!(wd->pci_slots & (1UL << slot)))
            continue;

        // setup threshold levels for pipe-chain
        for (uint32_t i = 0; i < 5; i ++)
        {
            _wd_write_32(&wd->pci[slot], 0x10<<2, i);
            _wd_write_32(&wd->pci[slot], 0x13<<2, 0);
            _wd_write_32(&wd->pci[slot], 0x14<<2, (200 << 0) | (200 << 12));
        }
        // sha_pad thresholds
        _wd_write_32(&wd->pci[slot], 0x10<<2, 0);
        _wd_write_32(&wd->pci[slot], 0x13<<2, 0);
        _wd_write_32(&wd->pci[slot], 0x14<<2, 10 | (10 << 12));
        // send fails back
        _wd_write_32(&wd->pci[slot], 0x11<<2, send_fails);

        _wd_set_vdip_64(wd, slot, 0, dma_phys);
        _wd_set_vdip_64(wd, slot, 1, ((wd->sv.req_depth-1) << 5) | 0x1f);
    }
}

void
wd_ed25519_verify_init_resp( wd_wksp_t *        wd)
{
    (void)wd;
}

int
wd_ed25519_verify_req( wd_wksp_t *   wd,
                       void const *  msg,
                       ulong         sz,
                       void const *  sig,
                       void const *  public_key,
                       uint64_t      m_seq,
                       uint32_t      m_chunk,
                       uint16_t      m_ctrl,
                       uint16_t      m_sz)
{
    uint32_t slot = wd->sv.req_slot;
    uint32_t src = 0;

    // Every sixteen requests we check for backpressure
    // this check is one PCIe RTT (~1us), we try to avoid
    // it as much as possible
    if (!(m_seq & 0xf))
    {
        int i;
        // we cycle through all PCIe slots available to us
        // whichever slot is not backpressured we use that next
        for (i = 0; i < WD_TRY_LIMIT; i ++, slot = _wd_next_slot(wd, slot))
        {
            uint32_t fill = _wd_read_32(&wd->pci[slot], (0x21+src)<<2);
            // PCIe buffer level
            if ((fill & 0xfff) > 0)
                continue;
            // number of pending transactions in pipe-chain
            if (((fill >> 12) & 0x3ff) > 256)
                continue;
            // DMA buffer level
            if (((fill >> 22) & 0x3ff) > 256)
                continue;
            break;
        }
        // timeout
        if (i == WD_TRY_LIMIT)
            return -1;
    }

    uint64_t dma_addr = fd_mcache_line_idx(m_seq, wd->sv.req_depth) << 5;

    wd->stream_buf[0] = WD_PCI_MAGIC;
    wd->stream_buf[1] = src | (((uint32_t)sz + 32 + 32) << 16);
    wd->stream_buf[2] = (uint32_t)((uint32_t)(m_sz) | (((uint32_t)m_ctrl) << 16));
    wd->stream_buf[3] = (uint32_t)((dma_addr >>  0) & 0xFFFFFFFF);
    wd->stream_buf[4] = (uint32_t)((dma_addr >> 32) & 0xFFFFFFFF);
    wd->stream_buf[5] = (uint32_t)((m_seq >>  0) & 0xFFFFFFFF);
    wd->stream_buf[6] = (uint32_t)((m_seq >> 32) & 0xFFFFFFFF);
    wd->stream_buf[7] = m_chunk;

    _wd_stream_256(wd, slot, wd->stream_buf);

    // unfortunately we cannot avoid this copy as we don't
    // make assumptions about the incoming buffer's
    // alignment, which is required for avx streaming
    memcpy(wd->stream_buf, ((uint8_t*)sig)+0, 32);
    _wd_stream_256(wd, slot, wd->stream_buf);

    memcpy(wd->stream_buf, ((uint8_t*)sig)+32, 32);
    _wd_stream_256(wd, slot, wd->stream_buf);

    memcpy(wd->stream_buf, public_key, 32);
    _wd_stream_256(wd, slot, wd->stream_buf);
    uint32_t i;
    for (i = 0; i < sz; i += 32)
    {
        memcpy(wd->stream_buf, ((uint8_t*)msg) + i, 32);
        _wd_stream_256(wd, slot, wd->stream_buf);
    }

    // pad the stream for the sake of 512-bit wide PCIe endpoint in AWS-F1
    if ((i / 32) & 1)
        _wd_stream_256(wd, slot, wd->stream_buf);

    // flush write-combining buffers
    _wd_stream_flush(wd, slot);

    wd->sv.req_slot = slot;

    return 0;
}
