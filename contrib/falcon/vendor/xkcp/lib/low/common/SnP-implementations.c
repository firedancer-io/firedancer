/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Implementation by Gilles Van Assche and Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include <stdio.h>
#include "config.h"
#include "PlSnP-common.h"
#include "SnP-common.h"
#ifdef XKCP_has_KeccakP1600
    #include "KeccakP-1600-SnP.h"
#endif
#ifdef XKCP_has_KeccakP1600times2
    #include "KeccakP-1600-times2-SnP.h"
#endif
#ifdef XKCP_has_KeccakP1600times4
    #include "KeccakP-1600-times4-SnP.h"
#endif
#ifdef XKCP_has_KeccakP1600times8
    #include "KeccakP-1600-times8-SnP.h"
#endif
#ifdef XKCP_has_Xoodoo
    #include "Xoodoo-SnP.h"
#endif
#ifdef XKCP_has_Xoodootimes4
    #include "Xoodoo-times4-SnP.h"
#endif
#ifdef XKCP_has_Xoodootimes8
    #include "Xoodoo-times8-SnP.h"
#endif
#ifdef XKCP_has_Xoodootimes16
    #include "Xoodoo-times16-SnP.h"
#endif

void XKCP_PrintImplementations()
{
    int SnP_feature_mask = ~0;
    int PlSnP_feature_mask = ~0;

    #ifdef XKCP_has_KeccakP1600
    printf("Keccak-p[1600]\303\2271: %s\n", KeccakP1600_GetImplementation());
    if (KeccakP1600_GetFeatures() & SnP_feature_mask & SnP_Feature_SpongeAbsorb) {
        printf("      + optimized sponge absorb loop\n");
    }
    if (KeccakP1600_GetFeatures() & SnP_feature_mask & SnP_Feature_OD) {
        printf("      + optimized OD duplexing\n");
    }
    #elif 0
    printf("Keccak-p[1600]\303\2271 not compiled in\n");
    #endif

    #if defined(XKCP_has_KeccakP1600times2)
    printf("Keccak-p[1600]\303\2272: %s\n", KeccakP1600times2_GetImplementation());
    if (KeccakP1600times2_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_SpongeAbsorb) {
        printf("      + optimized parallel sponge absorb loop\n");
    }
    if (KeccakP1600times2_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_Farfalle) {
        printf("      + optimized Kravatte compress and expand loops\n");
    }
    if (KeccakP1600times2_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_KangarooTwelve) {
        printf("      + optimized KangarooTwelve parallel leaves processing\n");
    }
    #elif 0
    printf("Keccak-p[1600]\303\2272 not compiled in\n");
    #endif

    #if defined(XKCP_has_KeccakP1600times4)
    printf("Keccak-p[1600]\303\2274: %s\n", KeccakP1600times4_GetImplementation());
    if (KeccakP1600times4_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_SpongeAbsorb) {
        printf("      + optimized parallel sponge absorb loop\n");
    }
    if (KeccakP1600times4_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_Farfalle) {
        printf("      + optimized Kravatte compress and expand loops\n");
    }
    if (KeccakP1600times4_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_KangarooTwelve) {
        printf("      + optimized KangarooTwelve parallel leaves processing\n");
    }
    #elif 0
    printf("Keccak-p[1600]\303\2272 not compiled in\n");
    #endif

    #if defined(XKCP_has_KeccakP1600times8)
    printf("Keccak-p[1600]\303\2278: %s\n", KeccakP1600times8_GetImplementation());
    if (KeccakP1600times8_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_SpongeAbsorb) {
        printf("      + optimized parallel sponge absorb loop\n");
    }
    if (KeccakP1600times8_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_Farfalle) {
        printf("      + optimized Kravatte compress and expand loops\n");
    }
    if (KeccakP1600times8_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_KangarooTwelve) {
        printf("      + optimized KangarooTwelve parallel leaves processing\n");
    }
    #elif 0
    printf("Keccak-p[1600]\303\2278 not compiled in\n");
    #endif

    #ifdef XKCP_has_Xoodoo
    printf("Xoodoo\303\2271: %s\n", Xoodoo_GetImplementation());
    if (Xoodoo_GetFeatures() & SnP_feature_mask & SnP_Feature_SpongeAbsorb) {
        printf("      + optimized sponge absorb loop\n");
    }
    if (Xoodoo_GetFeatures() & SnP_feature_mask & SnP_Feature_OD) {
        printf("      + optimized OD duplexing\n");
    }
    if (Xoodoo_GetFeatures() & SnP_feature_mask & SnP_Feature_Cyclist) {
        printf("      + optimized Xoodyak full-block loops\n");
    }
    if (Xoodoo_GetFeatures() & SnP_feature_mask & SnP_Feature_Farfalle) {
        printf("      + optimized Xoofff compress and expand loops\n");
    }
    #elif 0
    printf("Xoodoo\303\2271 not compiled in\n");
    #endif

    #ifdef XKCP_has_Xoodootimes4
    printf("Xoodoo\303\2274: %s\n", Xoodootimes4_GetImplementation());
    if (Xoodootimes4_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_SpongeAbsorb) {
        printf("      + optimized parallel sponge absorb loop\n");
    }
    if (Xoodootimes4_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_Farfalle) {
        printf("      + optimized Xoofff compress and expand loops\n");
    }
    #elif 0
    printf("Xoodoo\303\2274 not compiled in\n");
    #endif

    #ifdef XKCP_has_Xoodootimes8
    printf("Xoodoo\303\2278: %s\n", Xoodootimes8_GetImplementation());
    if (Xoodootimes8_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_SpongeAbsorb) {
        printf("      + optimized parallel sponge absorb loop\n");
    }
    if (Xoodootimes8_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_Farfalle) {
        printf("      + optimized Xoofff compress and expand loops\n");
    }
    #elif 0
    printf("Xoodoo\303\2278 not compiled in\n");
    #endif

    #ifdef XKCP_has_Xoodootimes16
    printf("Xoodoo\303\22716: %s\n", Xoodootimes16_GetImplementation());
    if (Xoodootimes16_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_SpongeAbsorb) {
        printf("      + optimized parallel sponge absorb loop\n");
    }
    if (Xoodootimes16_GetFeatures() & PlSnP_feature_mask & PlSnP_Feature_Farfalle) {
        printf("      + optimized Xoofff compress and expand loops\n");
    }
    #elif 0
    printf("Xoodoo\303\22716 not compiled in\n");
    #endif
}
