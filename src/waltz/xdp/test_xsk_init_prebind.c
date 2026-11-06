#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <net/if.h>
#include "fd_xsk.h"
#include "../../util/log/fd_log.h"
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);abort();}}while(0)
static void mock_log(char const *fmt,...){(void)fmt;}
#undef FD_LOG_WARNING
#undef FD_LOG_INFO
#undef FD_LOG_NOTICE
#undef FD_LOG_ERR
#define FD_LOG_WARNING(a) mock_log a
#define FD_LOG_INFO(a) mock_log a
#define FD_LOG_NOTICE(a) mock_log a
#define FD_LOG_ERR(a) do {mock_log a;abort();}while(0)
char const *fd_io_strerror(int e){(void)e;return "mock";}
static unsigned sockets,binds,closes,maps,unmaps,option_reads;
static unsigned expect_count;static unsigned long expect_off;
static int fail_bind,fail_option,fail_map,dirty_fill;
static void *fill;
static int mock_socket(int a,int b,int c){CHECK(a==AF_XDP);(void)b;(void)c;sockets++;return 77;}
static int mock_close(int f){CHECK(f==77);closes++;return 0;}
static int mock_setsockopt(int f,int l,int n,void const *p,socklen_t z){CHECK(f==77);(void)l;(void)n;(void)p;(void)z;return 0;}
static int mock_getsockopt(int f,int l,int n,void *p,socklen_t *z){CHECK(f==77&&l==SOL_XDP);
 if(n==XDP_MMAP_OFFSETS){struct xdp_mmap_offsets *o=p;memset(o,0,sizeof(*o));struct xdp_ring_offset v={.producer=0,.consumer=4,.flags=8,.desc=64};o->rx=o->tx=o->fr=o->cr=v;*z=sizeof(*o);return 0;}
 CHECK(n==XDP_OPTIONS);option_reads++;((struct xdp_options *)p)->flags=fail_option?0:XDP_OPTIONS_ZEROCOPY;*z=sizeof(struct xdp_options);return 0;
}
static void *mock_mmap(void *a,size_t n,int p,int fl,int fd,off_t off){(void)a;(void)p;(void)fl;CHECK(fd==77);maps++;
 if((int)maps==fail_map){errno=ENOMEM;return MAP_FAILED;}
 void *m=calloc(1,n);CHECK(m);if(off==XDP_UMEM_PGOFF_FILL_RING){fill=m;if(dirty_fill)*(unsigned *)m=1;}return m;
}
static int mock_munmap(void *p,size_t n){(void)n;unmaps++;free(p);return 0;}
static long mock_syscall(long n,...){CHECK(n==SYS_mlock);return 0;}
static int mock_bind(int f,struct sockaddr const *a,socklen_t n){CHECK(f==77);(void)n;binds++;
 struct sockaddr_xdp const *s=(void const *)a;CHECK(fill);CHECK(s->sxdp_queue_id==0);CHECK(*(unsigned *)fill==expect_count);
 if(expect_count){CHECK(s->sxdp_flags&XDP_ZEROCOPY);unsigned long *d=(void *)((char *)fill+64);CHECK(d[0]==expect_off);CHECK(d[expect_count-1]==expect_off+(expect_count-1)*2048UL);*(unsigned *)((char *)fill+4)=512;}
 if(fail_bind){errno=EOPNOTSUPP;return -1;}return 0;
}
static ssize_t mock_sendto(int f,void const *b,size_t n,int fl,struct sockaddr const *a,socklen_t z){CHECK(f==77);(void)b;(void)n;(void)fl;(void)a;(void)z;return 0;}
static char *mock_if_indextoname(unsigned n,char *b){(void)n;strcpy(b,"mock0");return b;}
static int mock_fcntl(int f,int c,...){(void)f;(void)c;return 0;}
#define socket mock_socket
#define close mock_close
#define setsockopt mock_setsockopt
#define getsockopt mock_getsockopt
#define mmap mock_mmap
#define munmap mock_munmap
#define syscall mock_syscall
#define bind mock_bind
#define sendto mock_sendto
#define if_indextoname mock_if_indextoname
#define fcntl mock_fcntl
#include "fd_xsk.c"
static void reset(void){sockets=binds=closes=maps=unmaps=option_reads=0;expect_count=0;expect_off=0;fail_bind=fail_option=fail_map=dirty_fill=0;fill=NULL;}
int main(void){
 void *mem=NULL;CHECK(!posix_memalign(&mem,4096,8UL*1024*1024));
 fd_xsk_params_t p={.fr_depth=2048,.rx_depth=1024,.cr_depth=1024,.tx_depth=1024,.umem_addr=mem,.frame_sz=2048,.umem_sz=8UL*1024*1024,.if_idx=2,.if_queue_id=0,.bind_flags=XDP_COPY};
 fd_xsk_t x;
 reset();CHECK(fd_xsk_init(&x,&p)==&x);CHECK(binds==1&&option_reads==0);fd_xsk_fini(&x);CHECK(closes==1&&unmaps==4);
 p.bind_flags=XDP_ZEROCOPY;
 reset();CHECK(fd_xsk_init(&x,&p)==&x);CHECK(binds==1&&option_reads==0);fd_xsk_fini(&x);CHECK(closes==1&&unmaps==4);
 p.if_idx=1;p.bind_flags=XDP_COPY;
 reset();CHECK(fd_xsk_init(&x,&p)==&x);CHECK(binds==1&&option_reads==0);fd_xsk_fini(&x);CHECK(closes==1&&unmaps==4);
 p.if_idx=2;p.bind_flags=XDP_ZEROCOPY;
 p.initial_fill_off=2UL*1024*1024;p.initial_fill_cnt=1024;
 reset();expect_count=1024;expect_off=p.initial_fill_off;CHECK(fd_xsk_init(&x,&p)==&x);CHECK(option_reads==1&&x.ring_fr.cached_prod==1024&&*x.ring_fr.cons==512);fd_xsk_fini(&x);CHECK(closes==1&&unmaps==4);
 reset();p.bind_flags=XDP_COPY;CHECK(!fd_xsk_init(&x,&p));CHECK(sockets==0);p.bind_flags=XDP_ZEROCOPY;
 reset();expect_count=1024;expect_off=p.initial_fill_off;fail_bind=1;CHECK(!fd_xsk_init(&x,&p));CHECK(binds==1&&option_reads==0&&closes==1&&unmaps==4);
 reset();expect_count=1024;expect_off=p.initial_fill_off;fail_option=1;CHECK(!fd_xsk_init(&x,&p));CHECK(binds==1&&option_reads==1&&closes==1&&unmaps==4);
 reset();fail_map=3;CHECK(!fd_xsk_init(&x,&p));CHECK(binds==0&&closes==1&&unmaps==2);
 reset();dirty_fill=1;CHECK(!fd_xsk_init(&x,&p));CHECK(binds==0&&closes==1&&unmaps==4);
 free(mem);puts("actual fd_xsk_init mocked-syscall regression PASS (9 cases; no sockets)");return 0;
}
