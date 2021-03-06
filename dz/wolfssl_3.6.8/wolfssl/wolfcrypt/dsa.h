/* dsa.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */


#ifndef WOLF_CRYPT_DSA_H
#define WOLF_CRYPT_DSA_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_DSA

#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/random.h>

/* for DSA reverse compatibility */
#define InitDsaKey wc_InitDsaKey
#define FreeDsaKey wc_FreeDsaKey
#define DsaSign wc_DsaSign
#define DsaVerify wc_DsaVerify
#define DsaPublicKeyDecode wc_DsaPublicKeyDecode
#define DsaPrivateKeyDecode wc_DsaPrivateKeyDecode
#define DsaKeyToDer wc_DsaKeyToDer

#ifdef __cplusplus
    extern "C" {
#endif


enum {
    DSA_PUBLIC   = 0,
    DSA_PRIVATE  = 1
};

/* DSA */
typedef struct DsaKey {
    mp_int p, q, g, y, x;
    int type;                               /* public or private */
} DsaKey;

WOLFSSL_API void wc_InitDsaKey(DsaKey* key);
WOLFSSL_API void wc_FreeDsaKey(DsaKey* key);
WOLFSSL_API int wc_DsaSign(const byte* digest, byte* out,
                           DsaKey* key, WC_RNG* rng);
WOLFSSL_API int wc_DsaVerify(const byte* digest, const byte* sig,
                             DsaKey* key, int* answer);
WOLFSSL_API int wc_DsaPublicKeyDecode(const byte* input, word32* inOutIdx,
                                      DsaKey*, word32);
WOLFSSL_API int wc_DsaPrivateKeyDecode(const byte* input, word32* inOutIdx,
                                       DsaKey*, word32);
WOLFSSL_API int wc_DsaKeyToDer(DsaKey* key, byte* output, word32 inLen);

#ifdef WOLFSSL_KEY_GEN
WOLFSSL_API int wc_MakeDsaKey(WC_RNG *rng, DsaKey *dsa);
WOLFSSL_API int wc_MakeDsaParameters(WC_RNG *rng, int modulus_size, DsaKey *dsa);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_DSA */
#endif /* WOLF_CRYPT_DSA_H */

