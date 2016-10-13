/* options.h.in
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */


/* default blank options for autoconf */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif


#undef  OPENSSL_EXTRA
#define OPENSSL_EXTRA

#undef  SINGLE_THREADED
#define SINGLE_THREADED

#undef  HAVE_THREAD_LS
#define HAVE_THREAD_LS

#undef  HAVE_AESGCM
#define HAVE_AESGCM

#undef  WOLFSSL_RIPEMD
#define WOLFSSL_RIPEMD

#undef  WOLFSSL_SHA512
#define WOLFSSL_SHA512

#undef  WOLFSSL_SHA384
#define WOLFSSL_SHA384

#undef  SESSION_CERTS
#define SESSION_CERTS

#undef  WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_GEN

#undef  HAVE_ECC
#define HAVE_ECC

#undef  TFM_ECC256
#define TFM_ECC256

#undef  ECC_SHAMIR
#define ECC_SHAMIR

#undef  WOLFSSL_ALLOW_SSLV3
#define WOLFSSL_ALLOW_SSLV3

#undef  NO_RC4
#define NO_RC4

#undef  NO_HC128
#define NO_HC128

#undef  NO_RABBIT
#define NO_RABBIT

#undef  HAVE_POLY1305
#define HAVE_POLY1305

#undef  HAVE_ONE_TIME_AUTH
#define HAVE_ONE_TIME_AUTH

#undef  HAVE_CHACHA
#define HAVE_CHACHA

#undef  HAVE_HASHDRBG
#define HAVE_HASHDRBG

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SNI
#define HAVE_SNI

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_ALPN
#define HAVE_ALPN

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  WOLFSSL_TEST_CERT
#define WOLFSSL_TEST_CERT

#undef  NO_PSK
#define NO_PSK

#undef  NO_MD4
#define NO_MD4

#undef  USE_FAST_MATH
#define USE_FAST_MATH

#undef  WOLFSSL_X86_64_BUILD
#define WOLFSSL_X86_64_BUILD

#ifdef __cplusplus
}
#endif

