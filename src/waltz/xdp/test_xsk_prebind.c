/* Pure offline tests: no socket, mmap, BPF, module or host calls. */
#include "fd_xsk_prebind.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CHECK(c) do { if( !(c) ) { fprintf(stderr,"check failed line %d: %s\n",__LINE__,#c); abort(); } } while(0)

int main( void ) {
  fd_xsk_prebind_layout_t l;
  unsigned long frames=64UL+128UL+1024UL+1024UL;
  CHECK( !fd_xsk_prebind_layout(&l,frames*2048UL,2048UL,64UL,128UL,1024UL,1024UL) );
  CHECK(l.tx_off==0UL && l.cache_off==64UL*2048UL && l.phys_off==192UL*2048UL);
  CHECK(l.loop_off==1216UL*2048UL && l.end_off==frames*2048UL);
  fd_xsk_prebind_layout_t before=l;
  CHECK(fd_xsk_prebind_layout(&l,(frames-1UL)*2048UL,2048UL,64UL,128UL,1024UL,1024UL));
  CHECK(!memcmp(&l,&before,sizeof(l)));
  CHECK(fd_xsk_prebind_layout(&l,ULONG_MAX,2048UL,1UL,1UL,1UL,1UL));
  CHECK(fd_xsk_prebind_layout(&l,2048UL,2048UL,ULONG_MAX,0UL,1UL,0UL));
  CHECK(fd_xsk_prebind_layout(&l,4096UL,1024UL,0UL,0UL,1UL,0UL));
  CHECK(fd_xsk_prebind_layout(&l,4096UL,2048UL,0UL,0UL,0UL,0UL));
  CHECK(!fd_xsk_prebind_layout(&l,1024UL*2048UL,2048UL,0UL,0UL,1024UL,0UL));
  CHECK(l.loop_off==l.end_off && l.loop_cnt==0UL);

  unsigned long d[2048]; for(unsigned i=0U;i<2048U;i++)d[i]=ULONG_MAX;
  unsigned int p=0U,c=0U,cp=0U,cc=0U;
  l=before;
  CHECK(!fd_xsk_prebind_publish(d,&p,&c,&cp,&cc,2048UL,l.phys_off,l.phys_cnt,l.end_off));
  CHECK(p==1024U && cp==1024U && !c && !cc);
  for(unsigned i=0U;i<1024U;i++)CHECK(d[i]==l.phys_off+(unsigned long)i*2048UL);
  CHECK(d[1024]==ULONG_MAX); /* loopback/TX/cache not published */
  CHECK(fd_xsk_prebind_publish(d,&p,&c,&cp,&cc,2048UL,l.phys_off,l.phys_cnt,l.end_off));
  CHECK(p==1024U && cp==1024U); /* no double bootstrap */
  for(unsigned which=0U;which<4U;which++) {
    p=c=cp=cc=0U;
    unsigned int * fields[4]={&p,&c,&cp,&cc}; *fields[which]=1U;
    CHECK(fd_xsk_prebind_publish(d,&p,&c,&cp,&cc,2048UL,l.phys_off,l.phys_cnt,l.end_off));
  }
  p=c=cp=cc=0U;unsigned long first=d[0];
  CHECK(fd_xsk_prebind_publish(d,&p,&c,&cp,&cc,511UL,0UL,1UL,l.end_off));
  CHECK(fd_xsk_prebind_publish(d,&p,&c,&cp,&cc,512UL,0UL,1024UL,l.end_off));
  CHECK(fd_xsk_prebind_publish(d,&p,&c,&cp,&cc,2048UL,1UL,1UL,l.end_off));
  CHECK(fd_xsk_prebind_publish(d,&p,&c,&cp,&cc,2048UL,ULONG_MAX,1UL,l.end_off));
  CHECK(fd_xsk_prebind_publish(d,&p,&c,&cp,&cc,2048UL,0UL,ULONG_MAX,l.end_off));
  CHECK(d[0]==first && !p && !cp);
  unsigned long max_aligned=ULONG_MAX-(ULONG_MAX%2048UL);
  unsigned long max_frames=max_aligned/2048UL;
  CHECK(!fd_xsk_prebind_layout(&l,max_aligned,2048UL,max_frames-1024UL,0UL,1024UL,0UL));
  CHECK(l.end_off==max_aligned);
  CHECK(fd_xsk_prebind_layout(&l,max_aligned,2048UL,max_frames-1024UL,0UL,1025UL,0UL));
  l=before;
  unsigned long loop[2048]; unsigned int lp=0U,lc=0U,lcp=0U,lcc=0U;
  CHECK(!fd_xsk_prebind_publish(loop,&lp,&lc,&lcp,&lcc,2048UL,l.loop_off,l.loop_cnt,l.end_off));
  CHECK(loop[0]==l.loop_off && loop[1023]+2048UL==l.end_off);
  CHECK(d[1023]+2048UL==loop[0]); /* physical and loopback spans touch, never overlap */
  puts("PASS prebind layout, bounds, disjoint spans, publication and double-bootstrap refusal (offline)");
  return 0;
}
