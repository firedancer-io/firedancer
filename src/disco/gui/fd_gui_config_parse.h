#ifndef HEADER_fd_src_disco_gui_fd_gui_config_parse_h
#define HEADER_fd_src_disco_gui_fd_gui_config_parse_h

#include "../../flamenco/fd_flamenco_base.h"

/* https://github.com/anza-xyz/agave/blob/master/account-decoder/src/validator_info.rs */
#define FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_NAME_SZ             (  80UL) /* +1UL for NULL terminator */
#define FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_WEBSITE_SZ          (  80UL)
#define FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_DETAILS_SZ          ( 300UL)
#define FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_ICON_URI_SZ         (  80UL)
#define FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_KEYBASE_USERNAME_SZ (  80UL)
#define FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_MAX_SZ              ( 576UL) /* does not include size of ConfigKeys */
#define FD_GUI_CONFIG_PARSE_MAX_VALID_ACCT_SZ                  (FD_GUI_CONFIG_PARSE_CONFIG_KEYS_MAX_SZ+FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_MAX_SZ)

/* The size of a ConfigKeys of length 2, which is the expected length of ValidatorInfo */
#define FD_GUI_CONFIG_PARSE_CONFIG_KEYS_MAX_SZ         (1UL + (32UL + 1UL)*2UL)

struct fd_gui_config_parse_info {
  fd_pubkey_t pubkey;
  char name    [ FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_NAME_SZ     + 1UL ]; /* +1UL for NULL */
  char website [ FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_WEBSITE_SZ  + 1UL ];
  char details [ FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_DETAILS_SZ  + 1UL ];
  char icon_uri[ FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_ICON_URI_SZ + 1UL ];
  char keybase_username[ FD_GUI_CONFIG_PARSE_VALIDATOR_INFO_KEYBASE_USERNAME_SZ + 1UL ];

  struct { ulong prev, next; } map;
  struct { ulong next; } pool;
};

typedef struct fd_gui_config_parse_info fd_gui_config_parse_info_t;

FD_PROTOTYPES_BEGIN

/* fd_gui_config_parse_validator_info parses the sz bytes at data as a
   ConfigProgram account holding a ValidatorInfo.  Returns 1 on success
   with info->pubkey and the string fields populated (a field that is
   absent, not a string, or longer than its max is set to the empty
   string).  Returns 0 if the account is not a ValidatorInfo or the
   JSON is malformed. */

int
fd_gui_config_parse_validator_info( uchar const *                data,
                                    ulong                        sz,
                                    fd_gui_config_parse_info_t * info );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_config_parse_h */
