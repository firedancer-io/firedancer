#include "fd_sysvar_slot_history.h"
#include "../fd_types.h"
#include "fd_sysvar.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L37 */
const ulong max_entries = 1024 * 1024;

/* TODO: move into seperate bitvec library */
const bits_per_block = 8 * sizeof(ulong);
void set( fd_slot_history_inner_t* bits, ulong i ) {
  ulong block_idx = i / bits_per_block;
  bits->blocks[ block_idx ] |= ( 1UL << ( i % bits_per_block ) );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L16 */
void fd_sysvar_slot_history_init( global_ctx_t* global ) {
  fd_slot_history_t history;
  /* How to initialize:
    - Two structures: fd_slot_history_t and fd_slot_history_inner_t
      - fd_slot_history_inner_t on heap
        - blocks_len (number of blocks): max_entries / ( bits_per_block )
        - blocks: malloc( sizeof(bitvec_block_t) * blocks_len )
      - fd_slot_history_t on stack (with memset=0) 
    - Set bit 0 to true
    - Set next_slot to 1 
   */

  /* Free malloc'd structure */
} 

void fd_sysvar_slot_history_update( global_ctx_t* global ) {

  /* Set current_slot, and update next_slot */

  /* TODO: handle case where current_slot > max_entries */

}

void fd_sysvar_slot_history_read( global_ctx_t* global, fd_slot_history_t* result ) {

  /* Deserialize case from  */

}
