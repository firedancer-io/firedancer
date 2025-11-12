# Program Cache Verification Integration Guide

## Quick Start

The comprehensive progcache verification provides extensive integrity checking beyond the basic funk verification. Here's how to integrate it into your codebase:

## 1. Basic Integration

Replace the existing simple verification with the comprehensive version:

### Before:
```c
void fd_progcache_verify( fd_progcache_admin_t * cache ) {
  FD_TEST( fd_funk_verify( cache->funk )==FD_FUNK_SUCCESS );
  FD_LOG_WARNING(( "progcache verify success" ));
}
```

### After:
```c
#include "fd_progcache_verify.h"

void fd_progcache_verify( fd_progcache_admin_t * cache ) {
  fd_progcache_verify_enhanced( cache );
}
```

## 2. Advanced Integration with User Cache

For more thorough verification including fork structure and visibility rules:

```c
#include "fd_progcache_verify.h"

// In your verification routine:
int verify_progcache_full( fd_progcache_admin_t * admin,
                           fd_progcache_t *       user,
                           ulong                  current_epoch_slot0 ) {

  int result = fd_progcache_verify_comprehensive( admin, user, current_epoch_slot0 );

  if( result != FD_FUNK_SUCCESS ) {
    FD_LOG_ERR(( "Progcache verification failed" ));
    // Handle error - possibly dump state for debugging
    return -1;
  }

  return 0;
}
```

## 3. Integration Points

### During Slot Processing

Add verification at key points in slot processing:

```c
// After completing a slot
fd_progcache_txn_advance_root( admin_cache, &slot_xid );
#ifdef FD_PROGCACHE_VERIFY
  fd_progcache_verify_enhanced( admin_cache );
#endif
```

### During Fork Switches

Verify after major fork operations:

```c
// After fork switch
fd_progcache_txn_attach_child( admin_cache, parent_xid, new_xid );
#ifdef FD_PROGCACHE_VERIFY
  if( fd_progcache_verify_comprehensive( admin_cache, user_cache, epoch_slot0 ) != FD_FUNK_SUCCESS ) {
    FD_LOG_WARNING(( "Fork switch verification failed" ));
  }
#endif
```

### In Test Suites

Add to existing test infrastructure:

```c
// In test_progcache.c
static void
test_comprehensive_verification( fd_wksp_t * wksp ) {
  // ... setup code ...

  // Run comprehensive verification
  FD_TEST( fd_progcache_verify_comprehensive( admin, user, epoch_slot0 ) == FD_FUNK_SUCCESS );

  // Test specific invariants
  // ... test code ...
}
```

## 4. Build Integration

### Update Makefile/Build System

Add the new verification source file to your build:

```makefile
# In src/flamenco/progcache/Local.mk (or equivalent)
$(call add-objs,fd_progcache_verify,fd_flamenco)
```

### Conditional Compilation

For production vs debug builds:

```c
#ifdef FD_DEBUG_MODE
  #define FD_PROGCACHE_VERIFY_LEVEL 2  // Comprehensive
#else
  #define FD_PROGCACHE_VERIFY_LEVEL 1  // Basic only
#endif

void progcache_verify_wrapper( fd_progcache_admin_t * cache ) {
#if FD_PROGCACHE_VERIFY_LEVEL >= 2
  fd_progcache_verify_enhanced( cache );
#elif FD_PROGCACHE_VERIFY_LEVEL >= 1
  FD_TEST( fd_funk_verify( cache->funk ) == FD_FUNK_SUCCESS );
#endif
}
```

## 5. Performance Considerations

The comprehensive verification is expensive (O(n²) for duplicate checking). Use strategically:

### Periodic Verification
```c
static ulong verify_counter = 0;
#define VERIFY_INTERVAL 1000  // Every 1000 operations

if( ++verify_counter % VERIFY_INTERVAL == 0 ) {
  fd_progcache_verify_comprehensive( admin, user, epoch_slot0 );
}
```

### On-Demand Verification
```c
// Add a signal handler or admin command
void handle_verify_signal( int sig ) {
  if( sig == SIGUSR1 ) {
    FD_LOG_NOTICE(( "Running progcache verification..." ));
    fd_progcache_verify_comprehensive( global_admin_cache, global_user_cache, current_epoch_slot0 );
  }
}
```

## 6. Error Handling

The verification functions return error codes that should be handled appropriately:

```c
int result = fd_progcache_verify_comprehensive( admin, user, epoch_slot0 );

switch( result ) {
  case FD_FUNK_SUCCESS:
    // All good
    break;

  case FD_FUNK_ERR_INVAL:
    // Invariant violation detected
    // Log details and possibly trigger recovery
    FD_LOG_ERR(( "Progcache corrupted, initiating recovery" ));
    fd_progcache_reset( admin );
    break;

  default:
    FD_LOG_ERR(( "Unknown verification error: %d", result ));
    break;
}
```

## 7. Monitoring and Metrics

Add metrics for verification results:

```c
struct progcache_verify_metrics {
  ulong verify_success_cnt;
  ulong verify_fail_cnt;
  ulong last_verify_timestamp;
  ulong last_fail_timestamp;
};

void monitored_verify( fd_progcache_admin_t * admin,
                       struct progcache_verify_metrics * metrics ) {
  ulong now = fd_log_wallclock();

  if( fd_progcache_verify_comprehensive( admin, NULL, 0UL ) == FD_FUNK_SUCCESS ) {
    metrics->verify_success_cnt++;
  } else {
    metrics->verify_fail_cnt++;
    metrics->last_fail_timestamp = now;
    // Trigger alert
  }

  metrics->last_verify_timestamp = now;
}
```

## 8. Debugging Support

When verification fails, gather diagnostic information:

```c
void dump_progcache_state( fd_progcache_admin_t * admin,
                           fd_progcache_t *       user,
                           const char *           filename ) {
  FILE * f = fopen( filename, "w" );
  if( !f ) return;

  fprintf( f, "=== PROGCACHE STATE DUMP ===\n" );
  fprintf( f, "Fork depth: %lu\n", user ? user->fork_depth : 0 );

  if( user ) {
    fprintf( f, "Fork XIDs:\n" );
    for( ulong i = 0; i < user->fork_depth; i++ ) {
      fprintf( f, "  [%lu]: %lu:%lu\n", i,
               user->fork[i].ul[0], user->fork[i].ul[1] );
    }
  }

  // Add more diagnostic info as needed

  fclose( f );
}

// Use in verification failure handler
if( verify_result != FD_FUNK_SUCCESS ) {
  dump_progcache_state( admin, user, "/tmp/progcache_dump.txt" );
}
```

## Summary

The comprehensive verification provides:
- **Memory safety**: Detects buffer overflows and invalid pointers
- **Logical consistency**: Ensures data structure invariants hold
- **Concurrency safety**: Identifies race conditions and atomicity violations
- **Debugging support**: Detailed error messages pinpoint issues

Integrate based on your needs:
- **Production**: Periodic verification or on-demand via admin commands
- **Testing**: Comprehensive verification after each operation
- **Development**: Enhanced verification with detailed logging

The verification overhead is acceptable for most use cases when run periodically rather than on every operation.