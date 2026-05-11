/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _x86_64_dispatch_h_
#define _x86_64_dispatch_h_

void XKCP_EnableAllCpuFeatures();
int XKCP_DisableSSSE3();
int XKCP_DisableAVX2();
int XKCP_DisableAVX512();
int XKCP_ProcessCpuFeatureCommandLineOption(const char * arg);

#endif
