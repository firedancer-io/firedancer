/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Xoodyak, designed by Joan Daemen, Seth Hoffert, Michaël Peeters, Gilles Van Assche and Ronny Van Keer.

Implementation by Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _Xoodyak_h_
#define _Xoodyak_h_

#include "config.h"
#ifdef XKCP_has_Xoodoo

#include <stddef.h>
#include "Cyclist.h"
#include "Xoodoo-SnP.h"
#include "Xoodyak-parameters.h"

KCP_DeclareCyclistStructure(Xoodyak, Xoodoo_state)
KCP_DeclareCyclistFunctions(Xoodyak)

#else
#error This requires an implementation of Xoodoo
#endif

#endif
