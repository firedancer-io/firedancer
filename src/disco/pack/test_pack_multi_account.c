/* Native pack regressions: wire inputs are parsed by fd_txn_parse, signatures
   are fake identity fields, and no signer/bank/validator is invoked. */
#ifndef FD_PACK_C_SOURCE
#define FD_PACK_C_SOURCE "fd_pack.c"
#endif
#include FD_PACK_C_SOURCE
#define main retained_native_suite_main
#include "test_pack.c"
#undef main
#include <stdio.h>

static fd_acct_addr_t mh,mk[2];
typedef struct { fd_txn_p_t t; } mp_msg_t;
static mp_msg_t mp_msg;
static fd_acct_addr_t mp_key(ulong kind,ulong id){fd_acct_addr_t k;memset(k.b,(int)kind,32UL);memcpy(k.b+1,&id,8UL);return k;}
static uchar * mp_sv(uchar * p,ulong n){while(n>=128UL){*p++=(uchar)((n&127UL)|128UL);n>>=7;}*p++=(uchar)n;return p;}
static uchar * mp_bytes(uchar * p,void const * b,ulong n){memcpy(p,b,n);return p+n;}
static uchar * mp_ix(uchar * p,uchar pg,uchar const * ac,ulong n,uchar const * d,ulong z){*p++=pg;p=mp_sv(p,n);p=mp_bytes(p,ac,n);p=mp_sv(p,z);return mp_bytes(p,d,z);}
static uchar * mp_prefix(mp_msg_t * out,ulong id,fd_acct_addr_t const * keys,ulong n,ulong readonly){
 memset(out,0,sizeof(*out));uchar * p=out->t.payload;*p++=1U;memcpy(p,&id,8UL);memset(p+8,0x55,56UL);p+=64UL;
 *p++=1U;*p++=0U;*p++=(uchar)readonly;p=mp_sv(p,n);p=mp_bytes(p,keys,32UL*n);memset(p,17,32UL);return p+32UL;
}
static void mp_parse(mp_msg_t * out,uchar * end){
 out->t.payload_sz=(ushort)(end-out->t.payload);FD_TEST(out->t.payload_sz<=FD_TPU_MTU);
 FD_TEST(fd_txn_parse(out->t.payload,out->t.payload_sz,TXN(&out->t),NULL));
}
static uchar * mp_budget(uchar * p,uchar pg,uint cu,ulong fee,uint loaded){
 ulong price=(fee*1000000UL+(ulong)cu-1UL)/(ulong)cu;uchar d[9];
 d[0]=2U;memcpy(d+1,&cu,4UL);p=mp_ix(p,pg,NULL,0UL,d,5UL);
 d[0]=3U;memcpy(d+1,&price,8UL);p=mp_ix(p,pg,NULL,0UL,d,9UL);
 d[0]=4U;memcpy(d+1,&loaded,4UL);return mp_ix(p,pg,NULL,0UL,d,5UL);
}
static void mp_read(mp_msg_t * out,ulong id,uint mask,int cross,ulong fee){
 fd_acct_addr_t keys[5]={cross?mh:mp_key('p',id),{{0}},{{0}},{{0}},{{0}}};
 memcpy(keys[1].b,FD_COMPUTE_BUDGET_PROGRAM_ID,32UL);ulong n=3UL;
 for(ulong j=0UL;j<2UL;j++)if(mask&(1U<<j))keys[n++]=mk[j];
 uchar * p=mp_prefix(out,id,keys,n,n-1UL);p=mp_sv(p,4UL);p=mp_budget(p,1U,1000U,fee,65536U);
 uchar ac[2]={0,0},d[20]={2,0,0,0};memcpy(d+12,&id,8UL);p=mp_ix(p,2U,ac,2UL,d,20UL);mp_parse(out,p);
}
static void mp_filler(mp_msg_t * out,ulong id){
 fd_acct_addr_t keys[2]={mh,{{0}}};uchar * p=mp_prefix(out,id,keys,2UL,1UL);p=mp_sv(p,1UL);
 uchar ac[2]={0,0},d[20]={2,0,0,0};memcpy(d+12,&id,8UL);p=mp_ix(p,1U,ac,2UL,d,20UL);mp_parse(out,p);
}
static void mp_tiny(mp_msg_t * out,ulong id,ulong fee){
 fd_acct_addr_t keys[4]={mp_key('p',id),mk[0],{{0}},{{0}}};memcpy(keys[2].b,FD_COMPUTE_BUDGET_PROGRAM_ID,32UL);
 uchar * p=mp_prefix(out,id,keys,4UL,2UL);p=mp_sv(p,4UL);p=mp_budget(p,2U,1000U,fee,65536U);
 uchar ac[2]={0,0},d[20]={2,0,0,0};memcpy(d+12,&id,8UL);p=mp_ix(p,3U,ac,2UL,d,20UL);mp_parse(out,p);
}
static void mp_canary(mp_msg_t * out,uint cu){
 /* Same300-byte native canary geometry:4096 CU/1M priority fee/loaded4096,
    System1-lamport transfer plus16 session bytes,tag and8-byte sequence. */
 fd_acct_addr_t keys[4]={mk[1],mp_key('s',9000UL),{{0}},{{0}}};memcpy(keys[3].b,FD_COMPUTE_BUDGET_PROGRAM_ID,32UL);
 uchar * p=mp_prefix(out,9000UL,keys,4UL,2UL);p=mp_sv(p,4UL);p=mp_budget(p,3U,cu,1000000UL,4096U);
 uchar ac[2]={0,1},d[37]={2,0,0,0,1};ulong id=9000UL;memset(d+12,0x11,16UL);memcpy(d+29,&id,8UL);
 p=mp_ix(p,2U,ac,2UL,d,37UL);mp_parse(out,p);FD_TEST(out->t.payload_sz==300U);
}
static fd_pack_ord_txn_t * mp_put(fd_pack_t * p,mp_msg_t const * m,ulong expiry){
 fd_txn_e_t * e=fd_pack_insert_txn_init(p);memcpy(e->txnp,&m->t,sizeof(m->t));ulong deleted;
 FD_TEST(fd_pack_insert_txn_fini(p,e,expiry,&deleted)==0 && !deleted);return(fd_pack_ord_txn_t *)e;
}
static void mp_verify(fd_pack_t * p){FD_TEST(!fd_pack_verify(p,pack_verify_scratch));}
static fd_pack_t * mp_init(ulong max_txn){
 fd_rng_new(_rng,0U,0UL);mh=mp_key('H',0UL);mk[0]=mp_key('K',0UL);mk[1]=mp_key('K',1UL);
 return init_all(512UL,4UL,max_txn,&outcome);
}
static void mp_done(fd_pack_t * p){mp_verify(p);fd_pack_clear_all(p);mp_verify(p);fd_pack_delete(fd_pack_leave(p));}
enum {MP_SAME=1,MP_DISJOINT=2,MP_ZERO=4,MP_CROSS=8,MP_ONLY=16,MP_HEAVY=32,MP_LOCK=64};
typedef struct {ulong tiny,target,H,disjoint,first;} mp_counts_t;
static void mp_drain(fd_pack_t * p,ulong bank,ulong depth,mp_counts_t * c){
 for(ulong step=0UL;step<250UL;step++){
  /* Heavy requested1.4M-CU canary must fit the scheduler's budget. */
  ulong n=fd_pack_schedule_next_microblock(p,2000000UL,bank,FD_PACK_SCHEDULE_TXN,outcome.results);if(!n)break;
  for(ulong i=0UL;i<n;i++){
   ulong id=fd_ulong_load_8(outcome.results[i].txnp->payload+1UL);if(!c->first)c->first=id;
   if(id>=3000UL && id<3000UL+depth)c->tiny++;
   else if(id==9000UL)c->target++;
   else if(id>=1000UL && id<1065UL)c->H++;
   else if(id>=5000UL && id<5065UL)c->disjoint++;
   else FD_TEST(0);
  }
  FD_TEST(fd_pack_microblock_complete(p,bank)==1);
 }
}
static void mp_deep(char const * name,ulong depth,int flags){
 fd_pack_t * p=mp_init(flags&MP_LOCK?1UL:16UL);if(flags&MP_SAME)mk[0]=mk[1];
 if(flags&MP_CROSS)for(ulong i=0UL;i<65UL;i++){mp_filler(&mp_msg,1000UL+i);mp_put(p,&mp_msg,100UL);}
 if(flags&MP_DISJOINT)for(ulong i=0UL;i<65UL;i++){mp_read(&mp_msg,5000UL+i,1U,0,0UL);mp_put(p,&mp_msg,100UL);}
 uint mask=(flags&(MP_SAME|MP_DISJOINT|MP_ONLY))?2U:3U;
 for(ulong i=0UL;i<65UL;i++){
  mp_read(&mp_msg,2000UL+i,mask,!!(flags&MP_CROSS),0UL);fd_pack_ord_txn_t * r=mp_put(p,&mp_msg,10UL);
  FD_TEST(r->root==(flags&MP_CROSS?FD_ORD_TXN_ROOT_PENALTY(0):FD_ORD_TXN_ROOT_PENDING));
 }
 if(flags&MP_LOCK){
  mp_read(&mp_msg,8000UL,2U,0,10000000UL);mp_put(p,&mp_msg,100UL);
  FD_TEST(fd_pack_schedule_next_microblock(p,2000000UL,0UL,FD_PACK_SCHEDULE_TXN,outcome.results)==1UL);
  FD_TEST(fd_ulong_load_8(outcome.results[0].txnp->payload+1UL)==8000UL);
 }
 ulong tiny_rewards=0UL,tiny_compute=0UL;
 for(ulong i=0UL;i<depth;i++){
  mp_tiny(&mp_msg,3000UL+i,flags&MP_ZERO?0UL:1000000UL);fd_pack_ord_txn_t * t=mp_put(p,&mp_msg,100UL);
  FD_TEST(t->root==FD_ORD_TXN_ROOT_PENALTY(1));tiny_rewards=t->rewards;tiny_compute=t->compute_est;
 }
 uint cu=flags&MP_HEAVY?1400000U:4096U;mp_canary(&mp_msg,cu);
 fd_txn_t const * txn=TXN(&mp_msg.t);ulong price=fd_ulong_load_8(mp_msg.t.payload+txn->instr[1].data_off+1UL);
 ulong actual_fee=(price*(ulong)cu+999999UL)/1000000UL;
 fd_pack_ord_txn_t * target=mp_put(p,&mp_msg,100UL);FD_TEST(target->root==FD_ORD_TXN_ROOT_PENALTY(0));
 ulong target_rewards=target->rewards,target_compute=target->compute_est;
 if(depth)FD_TEST((flags&MP_ZERO) && !(flags&MP_HEAVY) ? tiny_rewards*target_compute<target_rewards*tiny_compute : tiny_rewards*target_compute>target_rewards*tiny_compute);
 printf("{\"case\":\"%s\",\"phase\":\"native_order\",\"tiny_rewards\":%lu,\"tiny_compute\":%lu,\"target_rewards\":%lu,\"target_compute\":%lu,\"target_request_CU\":%u,\"target_price\":%lu,\"target_priority_fee\":%lu}\n",name,tiny_rewards,tiny_compute,target_rewards,target_compute,cu,price,actual_fee);fflush(stdout);
 mp_verify(p);FD_TEST(fd_pack_expire_before(p,11UL)==65UL);mp_verify(p);
 /* Same-account depth control wakes the66th writer through K0 completion.
    Every other distinct K1 must already be eligible at the expiry boundary. */
 if(!(flags&MP_SAME))FD_TEST(target->root==FD_ORD_TXN_ROOT_PENDING);
 fd_pack_bitset_acct_mapping_t * q=bitset_map_query(p->acct_to_bitset,mk[1],NULL);FD_TEST(q && q->ref_cnt==(flags&MP_SAME?depth+1UL:1UL));
 mp_counts_t c={0};mp_drain(p,flags&MP_LOCK?1UL:0UL,depth,&c);
 if(flags&MP_LOCK){
  FD_TEST(c.target==0UL && c.tiny==depth && p->pending_txn_cnt==1UL);
  FD_TEST(acct_uses_query(p->acct_in_use,mk[1],NULL));
  FD_TEST(!fd_pack_schedule_next_microblock(p,2000000UL,1UL,FD_PACK_SCHEDULE_TXN,outcome.results));
  FD_TEST(fd_pack_microblock_complete(p,0UL)==1);mp_drain(p,1UL,depth,&c);
 }
 FD_TEST(c.tiny==depth && c.target==1UL && c.H==(flags&MP_CROSS?65UL:0UL) && c.disjoint==(flags&MP_DISJOINT?65UL:0UL));
 if(depth && !(flags&MP_DISJOINT))FD_TEST(c.first==((flags&MP_ZERO) && !(flags&MP_HEAVY)?9000UL:3000UL) || (c.first>=3000UL && c.first<3000UL+depth));
 FD_TEST(!p->pending_txn_cnt && !p->outstanding_microblock_mask);
 for(ulong i=0UL;i<3UL;i++){fd_pack_end_block(p);FD_TEST(!fd_pack_schedule_next_microblock(p,2000000UL,0UL,FD_PACK_SCHEDULE_TXN,outcome.results));mp_verify(p);}
 printf("{\"case\":\"%s\",\"phase\":\"complete\",\"tiny_completed\":%lu,\"target_completed\":%lu,\"H_completed\":%lu,\"disjoint_completed\":%lu,\"remaining\":%lu,\"execution_lock_control\":%d,\"native_verify\":true}\n",name,c.tiny,c.target,c.H,c.disjoint,p->pending_txn_cnt,!!(flags&MP_LOCK));mp_done(p);
}
/* Upstream fake-record controls exercise internal caller policy and hash-map
   relocation. Parsed wires above cover actual fee/compute/expiry/drain. */
static void mp_rekey(fd_txn_e_t * e){
 fd_txn_t const * txn=TXN(e->txnp);fd_acct_addr_t * a=(fd_acct_addr_t *)(e->txnp->payload+txn->acct_addr_off);
 for(ulong j=0UL;j<txn->acct_addr_cnt;j++){
  fd_acct_addr_t x;memset(x.b,'H',32UL);if(!memcmp(a[j].b,x.b,32UL))a[j]=mh;
  memset(x.b,'X',32UL);if(!memcmp(a[j].b,x.b,32UL))a[j]=mk[0];
  memset(x.b,'Y',32UL);if(!memcmp(a[j].b,x.b,32UL))a[j]=mk[1];
 }
}
static fd_pack_ord_txn_t * mp_fake(fd_pack_t * p,ulong id,ulong expiry,double priority,char const * w,char const * r){
 make_transaction(id,1000U,1024U,priority,w,r,NULL,NULL);fd_txn_e_t * e=fd_pack_insert_txn_init(p);memcpy(e->txnp,txnp_scratch+id,sizeof(fd_txn_p_t));mp_rekey(e);ulong deleted;
 FD_TEST(fd_pack_insert_txn_fini(p,e,expiry,&deleted)>=0 && !deleted);return(fd_pack_ord_txn_t *)e;
}
static void mp_policy(void){
 fd_pack_t * p=mp_init(16UL);fd_pack_ord_txn_t * reader[65];
 for(ulong i=0UL;i<65UL;i++)reader[i]=mp_fake(p,i,10UL,1.0,"","XY");
 fd_pack_ord_txn_t * a=mp_fake(p,200UL,100UL,12.0,"X",""),*b=mp_fake(p,201UL,100UL,11.0,"Y","");
 for(ulong i=0UL;i<65UL;i++)FD_TEST(delete_transaction(p,reader[i],0,0)==1UL);
 FD_TEST(a->root==FD_ORD_TXN_ROOT_PENALTY(1) && b->root==FD_ORD_TXN_ROOT_PENALTY(1));
 FD_TEST(!treap_ele_cnt(p->pending));mp_done(p);puts("{\"case\":\"twoK_caller_policy_zero\",\"pass\":true}");
}
static void mp_relocation(void){
 fd_pack_t * p=mp_init(16UL);ulong mask=penalty_map_slot_cnt(p->penalty_treaps)-1UL,seed=penalty_map_seed(p->penalty_treaps);
 ulong slot=(ulong)penalty_map_key_hash(mk[0],seed)&mask;int found=0;
 for(ulong n=1UL;n<1000000UL;n++){fd_acct_addr_t k=mp_key('Q',n);if(((ulong)penalty_map_key_hash(k,seed)&mask)==slot){mk[1]=k;found=1;break;}}FD_TEST(found);
 for(ulong i=0UL;i<65UL;i++)mp_fake(p,i,100UL,1.0,"","XY");
 mp_fake(p,180UL,10UL,2.0,"","XY");
 fd_pack_ord_txn_t * a=mp_fake(p,200UL,100UL,12.0,"X",""),*b=mp_fake(p,201UL,100UL,11.0,"Y","");
 mp_fake(p,202UL,100UL,10.0,"Y","");
 ulong before=(ulong)penalty_map_query(p->penalty_treaps,mk[1],NULL);FD_TEST(before);mp_verify(p);
 FD_TEST(fd_pack_delete_transaction(p,txnp_get_signatures(txnp_scratch+180UL))==1UL);
 fd_pack_penalty_treap_t * after=penalty_map_query(p->penalty_treaps,mk[1],NULL);
 FD_TEST(after && (ulong)after!=before && treap_ele_cnt(after->penalty_treap)==1UL);
 FD_TEST(!penalty_map_query(p->penalty_treaps,mk[0],NULL));
 FD_TEST(a->root==FD_ORD_TXN_ROOT_PENDING && b->root==FD_ORD_TXN_ROOT_PENDING);mp_done(p);
 puts("{\"case\":\"first_tree_removal_relocates_next_tree\",\"actual_relocation\":true,\"pass\":true}");
}
static void mp_bundle(int promote){
 fd_pack_t * p=mp_init(16UL);for(ulong i=0UL;i<64UL;i++)mp_fake(p,i,100UL,1.0,"","XY");
 fd_txn_e_t * slots[2];fd_txn_e_t * const * b=fd_pack_insert_bundle_init(p,slots,2UL);
 make_transaction1(b[0]->txnp,180UL,1000U,1024U,2.0,"Z","",NULL,NULL);
 make_transaction1(b[1]->txnp,181UL,1000U,1024U,2.0,"H","XY",NULL,NULL);mp_rekey(b[0]);mp_rekey(b[1]);
 fd_ed25519_sig_t sig;memcpy(&sig,txnp_get_signatures(b[0]->txnp),sizeof(sig));fd_pack_ord_txn_t * first=(fd_pack_ord_txn_t *)b[0];ulong deleted;
 FD_TEST(fd_pack_insert_bundle_fini(p,b,2UL,10UL,0,NULL,&deleted)>=0 && !deleted);
 fd_pack_ord_txn_t * a=mp_fake(p,200UL,100UL,12.0,"X",""),*c=mp_fake(p,201UL,100UL,11.0,"Y","");
 FD_TEST((promote?fd_pack_delete_transaction(p,&sig):delete_transaction(p,first,1,0))==2UL);
 FD_TEST(a->root==(promote?FD_ORD_TXN_ROOT_PENDING:FD_ORD_TXN_ROOT_PENALTY(1)) && c->root==(promote?FD_ORD_TXN_ROOT_PENDING:FD_ORD_TXN_ROOT_PENALTY(1)));mp_done(p);
 printf("{\"case\":\"twoK_bundle_policy\",\"promote\":%d,\"pass\":true}\n",promote);
}
int main(int argc,char ** argv){
 fd_boot(&argc,&argv);rng=fd_rng_join(fd_rng_new(_rng,0U,0UL));fd_metrics_register((ulong *)fd_metrics_new(metrics_scratch,0UL));extra_verify=1;
 if(argc>1 && !strcmp(argv[1],"heavy"))mp_deep("zero_priority_tiny_vs_heavy1400000",65UL,MP_ZERO|MP_HEAVY);
 else {
  mp_deep("twoK_deep65",65UL,0);mp_deep("twoK_deep65_crossH",65UL,MP_CROSS);
  mp_deep("twoK_shallow64",64UL,0);mp_deep("oneK_deep65",65UL,MP_SAME);
  mp_deep("deep65_disjoint",65UL,MP_DISJOINT);mp_deep("zero_priority_4096_control",65UL,MP_ZERO);
  mp_deep("target_only",0UL,MP_ONLY);mp_deep("zero_priority_tiny_vs_heavy1400000",65UL,MP_ZERO|MP_HEAVY);
  mp_deep("K1_execution_read_lock",65UL,MP_LOCK);mp_policy();mp_relocation();mp_bundle(0);mp_bundle(1);
 }
 fd_rng_delete(fd_rng_leave(rng));fd_halt();return 0;
}
