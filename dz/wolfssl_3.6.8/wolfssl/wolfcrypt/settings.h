/* settings.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */


/* Place OS specific preprocessor flags, defines, includes here, will be
   included into every file because types.h includes it */


#ifndef WOLF_CRYPT_SETTINGS_H
#define WOLF_CRYPT_SETTINGS_H

#ifdef __cplusplus
    extern "C" {
#endif

/* Uncomment next line if building for Freescale KSDK Bare Metal */
  #define FREESCALE_KSDK_BM

/* Uncomment next line if building for Freescale KSDK with FREERTOS */
/*  #define FREESCALE_KSDK_FREERTOS */

/* Uncomment next line if using Max Strength build */
/* #define WOLFSSL_MAX_STRENGTH */

/* Uncomment next line to enable deprecated less secure static DH suites */
/* #define WOLFSSL_STATIC_DH */

/* Uncomment next line to enable deprecated less secure static RSA suites */
/* #define WOLFSSL_STATIC_RSA */

#include <wolfssl/wolfcrypt/visibility.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <user_settings.h>
#endif

/* make sure old RNG name is used with CTaoCrypt FIPS */
#ifdef HAVE_FIPS
    #define WC_RNG RNG
#endif

#if defined (FSL_RTOS_FREE_RTOS) || defined (FREESCALE_KSDK_FREERTOS)
    #define FREESCALE_COMMON
    #define NO_FILESYSTEM
    #define NO_WOLFSSL_MEMORY
    #define USER_TICKS
    #define WOLFSSL_LWIP
    #define FREERTOS
    #undef FREESCALE_KSDK_BM
    #define FREESCALE_KSDK_FREERTOS 
#endif

#ifdef FREESCALE_KSDK_BM
    #define FREESCALE_COMMON
    #define WOLFSSL_USER_IO
    #define SINGLE_THREADED
    #define NO_FILESYSTEM
    #define USE_WOLFSSL_MEMORY
    #define USER_TICKS
	#define DEBUG_WOLFSSL
    //#define WOLFCRYPT_ONLY
#endif


#ifdef FREESCALE_COMMON
    #define SIZEOF_LONG_LONG 8
    #define NO_WRITEV
    #define NO_DEV_RANDOM
    #define NO_RABBIT
    #define NO_WOLFSSL_DIR
    #define USE_FAST_MATH

    #define USE_CERT_BUFFERS_2048
    #define BENCH_EMBEDDED

    #define TFM_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT

    #define HAVE_ECC
    #define HAVE_AESCCM
    #define HAVE_AESGCM
    #define WOLFSSL_AES_COUNTER (1)
    #define WOLFSSL_AES_DIRECT (1)
    #define NO_RC4

    #include "fsl_common.h"

    /* random seed */
    #define NO_OLD_RNGNAME
    #if defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0)
        #define FREESCALE_TRNG
    #elif defined(FSL_FEATURE_SOC_RNG_COUNT) && (FSL_FEATURE_SOC_RNG_COUNT > 0)
        #define FREESCALE_RNGA
    #elif !defined(FREESCALE_KSDK_BM) && !defined(FREESCALE_FREE_RTOS) && !defined(FREESCALE_KSDK_FREERTOS)
        #define FREESCALE_K70_RNGA
        /* #define FREESCALE_K53_RNGB */
    #endif

    /* HW crypto */
    /* automatic enable based on Kinetis feature */
    /* if case manual selection is required, for example for benchmarking purposes,
     * just define FREESCALE_USE_MMCAU or FREESCALE_USE_LTC or none of these two macros (for software only)
     * both can be enabled simultaneously as LTC has priority over MMCAU in source code.
     */
    /* #define FSL_HW_CRYPTO_MANUAL_SELECTION */
    #ifndef FSL_HW_CRYPTO_MANUAL_SELECTION
        #if defined(FSL_FEATURE_SOC_MMCAU_COUNT) && FSL_FEATURE_SOC_MMCAU_COUNT
            #define FREESCALE_USE_MMCAU
        #endif

        #if defined(FSL_FEATURE_SOC_LTC_COUNT) && FSL_FEATURE_SOC_LTC_COUNT
            #define FREESCALE_USE_LTC
        #endif
    #else
        /* #define FREESCALE_USE_MMCAU */
        /* #define FREESCALE_USE_LTC */
    #endif
#endif

#if defined(FREESCALE_USE_MMCAU)
    /* AES and DES */
    #define FREESCALE_MMCAU
    /* MD5, SHA-1 and SHA-256 */
    #define FREESCALE_MMCAU_SHA
#endif /* FREESCALE_USE_MMCAU */

#if defined(FREESCALE_USE_LTC)
    #if defined(FSL_FEATURE_SOC_LTC_COUNT) && FSL_FEATURE_SOC_LTC_COUNT
        #define FREESCALE_LTC
        #define LTC_BASE LTC0

        #if defined(FSL_FEATURE_LTC_HAS_DES) && FSL_FEATURE_LTC_HAS_DES
            #define FREESCALE_LTC_DES
        #endif

        #if defined(FSL_FEATURE_LTC_HAS_GCM) && FSL_FEATURE_LTC_HAS_GCM
            #define FREESCALE_LTC_AES_GCM
        #endif

        #if defined(FSL_FEATURE_LTC_HAS_PKHA) && FSL_FEATURE_LTC_HAS_PKHA
            #define FREESCALE_LTC_ECC
            #define FREESCALE_LTC_TFM
            #define LTC_MAX_INT_BYTES (256)

            /* ECC-256, ECC-224 and ECC-192 are supported by LTC PKHA acceleration */
            #ifdef HAVE_ECC
                #ifndef ECC_TIMING_RESISTANT
                    #define ECC_TIMING_RESISTANT (1)
                #endif
                #define HAVE_ECC192 (1)
                #define HAVE_ECC224 (1)
                #define LTC_MAX_ECC_BITS (256)
            #endif
        #endif
    #endif
#endif /* FREESCALE_USE_LTC */

/* FreeScale MMCAU hardware crypto has 4 byte alignment.
   However, fsl_mmcau.h gives API with no alignment requirements (4 byte alignment is managed internally by fsl_mmcau.c) */
#ifdef FREESCALE_MMCAU
    #define WOLFSSL_MMCAU_ALIGNMENT 0
    #ifndef FREESCALE_LTC
        #undef WOLFSSL_AES_COUNTER
    #endif
#endif

/* if using hardware crypto and have alignment requirements, specify the
   requirement here.  The record header of SSL/TLS will prvent easy alignment.
   This hint tries to help as much as possible.  */
#ifndef WOLFSSL_GENERAL_ALIGNMENT
    #ifdef WOLFSSL_AESNI
        #define WOLFSSL_GENERAL_ALIGNMENT 16
    #elif defined(XSTREAM_ALIGN)
        #define WOLFSSL_GENERAL_ALIGNMENT  4
    #elif defined(FREESCALE_MMCAU)
        #define WOLFSSL_GENERAL_ALIGNMENT  WOLFSSL_MMCAU_ALIGNMENT
    #else
        #define WOLFSSL_GENERAL_ALIGNMENT  0
    #endif
#endif

#if defined(WOLFSSL_GENERAL_ALIGNMENT) && (WOLFSSL_GENERAL_ALIGNMENT > 0)
    #if defined(_MSC_VER)
        #define XGEN_ALIGN __declspec(align(WOLFSSL_GENERAL_ALIGNMENT))
    #elif defined(__GNUC__)
        #define XGEN_ALIGN __attribute__((aligned(WOLFSSL_GENERAL_ALIGNMENT)))
    #else
        #define XGEN_ALIGN
    #endif
#else
    #define XGEN_ALIGN
#endif

/* user can specify what curves they want with ECC_USER_CURVES otherwise
 * all curves are on by default for now */
#ifndef ECC_USER_CURVES
    #ifndef HAVE_ALL_CURVES
        #define HAVE_ALL_CURVES
    #endif
#endif

/* If using the max strength build, ensure OLD TLS is disabled. */
#ifdef WOLFSSL_MAX_STRENGTH
    #undef NO_OLD_TLS
    #define NO_OLD_TLS
#endif

/* If not forcing to use ARC4 as the DRBG, always enable Hash_DRBG */
#undef HAVE_HASHDRBG
#ifndef WOLFSSL_FORCE_RC4_DRBG
    #define HAVE_HASHDRBG
#endif

/* Certificate Request Extensions needs decode extras */
#ifdef WOLFSSL_CERT_EXT
    #ifndef RSA_DECODE_EXTRA
        #define RSA_DECODE_EXTRA
    #endif
    #ifndef ECC_DECODE_EXTRA
        #define ECC_DECODE_EXTRA
    #endif
#endif

/* Place any other flags or defines here */

#ifdef __cplusplus
    }   /* extern "C" */
#endif

#endif
