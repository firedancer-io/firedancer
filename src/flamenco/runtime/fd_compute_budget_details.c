#include "fd_compute_budget_details.h"
#include "../vm/fd_vm.h"

void
fd_compute_budget_details_new( fd_compute_budget_details_t * details ) {
  details->has_compute_units_limit_update             = 0;
  details->has_compute_units_price_update             = 0;
  details->has_requested_heap_size                    = 0;
  details->has_loaded_accounts_data_size_limit_update = 0;

  details->compute_unit_limit              = 200000UL;
  details->compute_unit_price              = 0;
  details->compute_meter                   = 200000UL;
  details->heap_size                       = FD_VM_HEAP_DEFAULT;
  details->loaded_accounts_data_size_limit = FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT;

  details->num_builtin_instrs              = 0UL;
  details->num_non_builtin_instrs          = 0UL;

  details->requested_heap_size_instr_index = 0;
}
