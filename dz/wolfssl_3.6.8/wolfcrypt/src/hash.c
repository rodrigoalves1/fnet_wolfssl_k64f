/* hash.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if !defined(WOLFSSL_TI_HASH)

#include <wolfssl/wolfcrypt/hash.h>

#if !defined(NO_MD5)
void wc_Md5GetHash(Md5* md5, byte* hash)
{
    Md5 save = *md5 ;
    wc_Md5Final(md5, hash) ;
    *md5 = save ;
}

WOLFSSL_API void wc_Md5RestorePos(Md5* m1, Md5* m2) {
    *m1 = *m2 ;
}

#endif

#if !defined(NO_SHA)
int wc_ShaGetHash(Sha* sha, byte* hash)
{
    int ret ;
    Sha save = *sha ;
    ret = wc_ShaFinal(sha, hash) ;
    *sha = save ;
    return ret ;
}

WOLFSSL_API void wc_ShaRestorePos(Sha* s1, Sha* s2) {
    *s1 = *s2 ;
}

int wc_ShaHash(const byte* data, word32 len, byte* hash)
{
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    Sha* sha;
#else
    Sha sha[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    sha = (Sha*)XMALLOC(sizeof(Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha == NULL)
        return MEMORY_E;
#endif

    if ((ret = wc_InitSha(sha)) != 0) {
        WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
        wc_ShaUpdate(sha, data, len);
        wc_ShaFinal(sha, hash);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;

}

#endif /* !defined(NO_SHA) */

#if !defined(NO_SHA256)
int wc_Sha256GetHash(Sha256* sha256, byte* hash)
{
    int ret ;
    Sha256 save = *sha256 ;
    ret = wc_Sha256Final(sha256, hash) ;
    *sha256 = save ;
    return ret ;
}

WOLFSSL_API void wc_Sha256RestorePos(Sha256* s1, Sha256* s2) {
    *s1 = *s2 ;
}

int wc_Sha256Hash(const byte* data, word32 len, byte* hash)
{
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    Sha256* sha256;
#else
    Sha256 sha256[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    sha256 = (Sha256*)XMALLOC(sizeof(Sha256), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha256 == NULL)
        return MEMORY_E;
#endif

    if ((ret = wc_InitSha256(sha256)) != 0) {
        WOLFSSL_MSG("InitSha256 failed");
    }
    else if ((ret = wc_Sha256Update(sha256, data, len)) != 0) {
        WOLFSSL_MSG("Sha256Update failed");
    }
    else if ((ret = wc_Sha256Final(sha256, hash)) != 0) {
        WOLFSSL_MSG("Sha256Final failed");
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(sha256, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#endif /* !defined(NO_SHA256) */

#endif /* !defined(WOLFSSL_TI_HASH) */

#if defined(WOLFSSL_SHA512)
int wc_Sha512Hash(const byte* data, word32 len, byte* hash)
{
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    Sha512* sha512;
#else
    Sha512 sha512[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    sha512 = (Sha512*)XMALLOC(sizeof(Sha512), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha512 == NULL)
        return MEMORY_E;
#endif

    if ((ret = wc_InitSha512(sha512)) != 0) {
        WOLFSSL_MSG("InitSha512 failed");
    }
    else if ((ret = wc_Sha512Update(sha512, data, len)) != 0) {
        WOLFSSL_MSG("Sha512Update failed");
    }
    else if ((ret = wc_Sha512Final(sha512, hash)) != 0) {
        WOLFSSL_MSG("Sha512Final failed");
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(sha512, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#if defined(WOLFSSL_SHA384)
int wc_Sha384Hash(const byte* data, word32 len, byte* hash)
{
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    Sha384* sha384;
#else
    Sha384 sha384[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    sha384 = (Sha384*)XMALLOC(sizeof(Sha384), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha384 == NULL)
        return MEMORY_E;
#endif

    if ((ret = wc_InitSha384(sha384)) != 0) {
        WOLFSSL_MSG("InitSha384 failed");
    }
    else if ((ret = wc_Sha384Update(sha384, data, len)) != 0) {
        WOLFSSL_MSG("Sha384Update failed");
    }
    else if ((ret = wc_Sha384Final(sha384, hash)) != 0) {
        WOLFSSL_MSG("Sha384Final failed");
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(sha384, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#endif /* defined(WOLFSSL_SHA384) */
#endif /* defined(WOLFSSL_SHA512) */
