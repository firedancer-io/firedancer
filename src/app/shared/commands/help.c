#include "../fd_config.h"
#include "../fd_action.h"

#include <string.h>
#include <unistd.h>

extern action_t * ACTIONS[];

#define HELP_ARG_INDENT (3UL)
#define HELP_ARG_GAP    (4UL)  /* spaces between the flag column and its description */
#define HELP_ARG_MAX    (64UL) /* most arguments any single action emits */

/* fd_action_help is the builder passed to an action's args_help
   callback.  The callback emits arguments by calling fd_action_help_arg,
   which simply records them here; fd_action_help_print then formats the
   collected arguments into an aligned column. */

struct fd_action_help {
  ulong cnt;
  struct {
    char const * name;
    char const * value;
    char const * description;
  } args[ HELP_ARG_MAX ];
};

void
fd_action_help_arg( fd_action_help_t * help,
                    char const *       name,
                    char const *       value,
                    char const *       description ) {
  if( FD_UNLIKELY( help->cnt>=HELP_ARG_MAX ) ) FD_LOG_ERR(( "too many help arguments (max %lu); increase HELP_ARG_MAX", HELP_ARG_MAX ));
  help->args[ help->cnt ].name        = name;
  help->args[ help->cnt ].value       = value;
  help->args[ help->cnt ].description = description;
  help->cnt++;
}

/* help_print_desc prints desc starting at the current column, wrapping
   any embedded newlines so continuation lines align under the first.
   col is the flag column width chosen for this command. */

static void
help_print_desc( char const * desc,
                 ulong        col ) {
  ulong pad = HELP_ARG_INDENT + col + HELP_ARG_GAP;
  for(;;) {
    char const * nl = strchr( desc, '\n' );
    if( FD_LIKELY( !nl ) ) {
      FD_LOG_STDOUT(( "%s\n", desc ));
      break;
    }
    FD_LOG_STDOUT(( "%.*s\n%*s", (int)(nl-desc), desc, (int)pad, "" ));
    desc = nl+1UL;
  }
}

/* help_print_args renders a collected set of arguments under the given
   section header, sizing the flag column to the widest flag so the
   descriptions line up.  Does nothing if help is empty. */

static void
help_print_args( char const *             header,
                 fd_action_help_t const * help ) {
  if( FD_UNLIKELY( !help->cnt ) ) return;

  FD_LOG_STDOUT(( "%s\n", header ));

  ulong col = 0UL;
  for( ulong i=0UL; i<help->cnt; i++ ) {
    ulong len = strlen( help->args[ i ].name );
    if( help->args[ i ].value ) len += 1UL + strlen( help->args[ i ].value ); /* space + value */
    if( len>col ) col = len;
  }

  for( ulong i=0UL; i<help->cnt; i++ ) {
    char flag[ 64 ];
    if( help->args[ i ].value ) FD_TEST( fd_cstr_printf_check( flag, sizeof( flag ), NULL, "%s %s", help->args[ i ].name, help->args[ i ].value ) );
    else                        FD_TEST( fd_cstr_printf_check( flag, sizeof( flag ), NULL, "%s",    help->args[ i ].name                        ) );
    FD_LOG_STDOUT(( "%*s%-*s%*s", (int)HELP_ARG_INDENT, "", (int)col, flag, (int)HELP_ARG_GAP, "" ));
    help_print_desc( help->args[ i ].description, col );
  }
}

/* help_print_derived_usage prints a "Usage" line derived from the
   action's arguments.  Used when the action does not supply an explicit
   .usage field.  Positional arguments are listed in order so required
   positionals are never hidden, followed by a trailing `[OPTIONS]`.  An
   action only needs to set .usage field when it has structure this
   simple default cannot express (e.g. a `<a|b|c>` subcommand choice). */
static void
help_print_derived_usage( action_t const *         action,
                          fd_action_help_t const * help ) {
  char usage[ 256 ];
  char * p   = fd_cstr_init( usage );
  char * end = usage + sizeof(usage);

  for( ulong i=0UL; i<help->cnt; i++ ) {
    char const * name = help->args[ i ].name;
    if( name[ 0 ]=='-' ) continue; /* a flag, covered by the [OPTIONS] below */

    char piece[ 96 ];
    ulong piece_len;
    if( help->args[ i ].value ) FD_TEST( fd_cstr_printf_check( piece, sizeof(piece), &piece_len, " %s %s", name, help->args[ i ].value ) );
    else                        FD_TEST( fd_cstr_printf_check( piece, sizeof(piece), &piece_len, " %s",    name                        ) );
    FD_TEST( piece_len < (ulong)(end-p) );
    p = fd_cstr_append_cstr( p, piece );
  }

  FD_TEST( 10UL < (ulong)(end-p) );
  p = fd_cstr_append_cstr( p, " [OPTIONS]" );
  fd_cstr_fini( p );

  FD_LOG_STDOUT(( "Usage: %s %s%s\n\n", FD_BINARY_NAME, action->name, usage ));
}

void
fd_action_help_print( action_t const * action ) {
  FD_LOG_STDOUT(( "%s\n", action->description ));

  if( FD_LIKELY( action->detail ) ) FD_LOG_STDOUT(( "\n%s\n", action->detail ));

  FD_LOG_STDOUT(( "\n" ));

  fd_action_help_t help[1] = {0};
  if( FD_LIKELY( action->args_help ) ) action->args_help( help );

  if( FD_LIKELY( action->usage ) ) FD_LOG_STDOUT(( "Usage: %s %s\n\n", FD_BINARY_NAME, action->usage ));
  else                             help_print_derived_usage( action, help );

  fd_action_help_t global[1] = {0};
  fd_global_options_help( global );
  help_print_args( "GLOBAL OPTIONS:", global );

  if( FD_LIKELY( help->cnt ) ) {
    FD_LOG_STDOUT(( "\n" ));
    help_print_args( "ARGUMENTS:", help );
  }
}

void
help_cmd_fn( args_t *   args   FD_PARAM_UNUSED,
             config_t * config FD_PARAM_UNUSED ) {
  FD_LOG_STDOUT(( "%s control binary\n\n", FD_APP_NAME ));
  FD_LOG_STDOUT(( "Usage: %s <SUBCOMMAND> [OPTIONS]\n\n", FD_BINARY_NAME ));

  fd_action_help_t global[1] = {0};
  fd_global_options_help( global );
  help_print_args( "OPTIONS:", global );

  FD_LOG_STDOUT(( "\nSUBCOMMANDS:\n" ));
  for( ulong i=0UL; ACTIONS[ i ]; i++ ) {
    FD_LOG_STDOUT(( "   %20s    %s\n", ACTIONS[ i ]->name, ACTIONS[ i ]->description ));
  }
}

action_t fd_action_help = {
  .name          = "help",
  .args          = NULL,
  .fn            = help_cmd_fn,
  .perm          = NULL,
  .description   = "Print this help message",
  .is_help       = 1,
  .is_immediate  = 1,
  .is_diagnostic = 1,
};
