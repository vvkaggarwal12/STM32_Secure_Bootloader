#ifndef __MBEDTLS_CONFIG_H__
#define __MBEDTLS_CONFIG_H__

#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME

/* mbed TLS feature support*/
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_PKCS1_V15  // Uncommented this
#define MBEDTLS_PKCS1_V21

/* mbed TLS modules */
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_MD_C
#define MBEDTLS_MD_WRAP_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRAP_C
#define MBEDTLS_RSA_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA1_C  // Added this
#define MBEDTLS_PKCS5_C // Added this
#define MBEDTLS_CIPHER_C // Added this

/* For test certificates */
#define MBEDTLS_CERTS_C
#define MBEDTLS_PEM_PARSE_C

/* For debugging */
#define MBEDTLS_ERROR_C
#define MBEDTLS_ERROR_STRERROR_DUMMY

/* RSA options */
#define MBEDTLS_RSA_NO_CRT

/* Entropy options */
// #define MBEDTLS_ENTROPY_HARDWARE_ALT

#include "mbedtls/check_config.h"

#endif /* __MBEDTLS_CONFIG_H__ */