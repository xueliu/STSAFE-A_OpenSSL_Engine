/**
 *********************************************************************************************
 * @file    pkey_test.c
 * @author  SMD application team
 * @version V1.0.0
 * @date    25-July-2020
 * @brief   Openssl STSAFE Engine test
 *********************************************************************************************
 * @attention
 *
 * <h2><center>&copy; COPYRIGHT 2020 STMicroelectronics</center></h2>
 *
 * Licensed under ST MYLIBERTY SOFTWARE LICENSE AGREEMENT (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *        http://www.st.com/myliberty
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied,
 * AND SPECIFICALLY DISCLAIMING THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *********************************************************************************************
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#include <stsafe_api.h>

#include "test_stsafe_engine.h"

#define MD_SIZE  32
#define SIG_SIZE 256

static const char *certificateFilename = "Device-Cert.pem";

extern int32_t pkey_test(void)
{
    int32_t       result      = 0;
    int           res         = 0;
    int           keysize     = 0;
    size_t        siglen      = 0;
    size_t        inlen       = 0;
    EVP_PKEY     *privkey     = NULL;
    EVP_PKEY     *pubKey      = NULL;
    EC_KEY       *eckey_pub   = NULL;
    EVP_PKEY_CTX *ctx         = NULL;
    ECDSA_SIG    *ecdsa_sig   = NULL;
    BIO          *bio_in      = NULL;
    X509         *certificate = NULL;
    long int      opensslerr  = 0;
    char          opensslerrbuff[1024];

    uint8_t       indata[MD_SIZE] = { 0 };
    unsigned char sig[SIG_SIZE]   = { 0 };
    const unsigned char *p        = (const unsigned char *)&sig;

    memset(opensslerrbuff, 0x00, 1024 * sizeof(char));

    printf("===== Setup for test\n");
    printf("===== Read certificate from STSAFE\n");

    /* use engine command to get certificate from memory region to file */
    if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_GET_DEVICE_CERT, 0, (void *)certificateFilename, 0)) {
        opensslerr = ERR_get_error();
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
        }
        printf("===== FAIL - Error from ENGINE_ctrl\n");
        printf("==========================================\n");
        result = -1;
    }

    if (result == 0) {
        printf("===== Certificate written to %s\n", certificateFilename);
        printf("===== Load private key via Engine\n");

        privkey = ENGINE_load_private_key(stsafe_engine, NULL, NULL, NULL);
        if (privkey == NULL) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from ENGINE_load_private_key\n");
            printf("==========================================\n");
            result = -1;
        }
    }

    if (result == 0) {
        if ( (keysize = EVP_PKEY_size(privkey) != 0)) {
            printf("===== privkey of size %d\n", keysize);
        } else {
            printf("===== Information - Cannot get privkey size\n");
        }

        ctx = EVP_PKEY_CTX_new(privkey, NULL);
        if (ctx == NULL) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from EVP_PKEY_CTX_new\n");
            printf("==========================================\n");
            result = -1;
        }
    }

    if (result == 0) {
        if ( (res = EVP_PKEY_sign_init(ctx)) <= 0) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from EVP_PKEY_sign_init\n");
            printf("==========================================\n");
            EVP_PKEY_CTX_free(ctx);
            result = -1;
        }
    }

    if (result == 0) {
        if ((res = EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256())) <= 0) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from EVP_PKEY_CTX_set_signature_md\n");
            printf("==========================================\n");
            EVP_PKEY_CTX_free(ctx);
            result = -1;
        }
    }

    if (result == 0) {
        printf("===== Generate digest\n");
        GenerateUnsignedChallenge(sizeof(indata), &indata[0]);
        unsigned int size = 0;
        if ( EVP_Digest(indata, MD_SIZE, &indata[0], &size, EVP_sha256(), NULL) == 0) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from EVP_Digest\n");
            printf("==========================================\n");
            EVP_PKEY_CTX_free(ctx);
            result = -1;
        }
        inlen = size;
    }

    if (result == 0) {
        siglen = SIG_SIZE;
        if (EVP_PKEY_sign(ctx, sig, &siglen, &indata[0], inlen) <= 0) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - siglen %d\n", siglen);
            printf("===== FAIL - Error from EVP_PKEY_sign\n");
            printf("==========================================\n");
            EVP_PKEY_CTX_free(ctx);
            result = -1;
        }
    }

    if (result == 0) {
        printf("===== Signing success\n");
        printf("===== Prepare verification\n");

        ecdsa_sig = ECDSA_SIG_new();
        if (ecdsa_sig == NULL) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from ECDSA_SIG_new\n");
            printf("==========================================\n");
            EVP_PKEY_CTX_free(ctx);
            result = -1;
        }
    }

    if (result == 0) {
        if (d2i_ECDSA_SIG(&ecdsa_sig, &p, siglen) == NULL) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from d2i_ECDSA_SIG\n");
            printf("==========================================\n");
            EVP_PKEY_CTX_free(ctx);
            result = -1;
        }
    }

    printf("===== Open %s file\n", certificateFilename);

    /* read device certificate from file */
    bio_in = BIO_new_file(certificateFilename, "r");
    if (bio_in == NULL) {
        opensslerr = ERR_get_error();
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
        }
        printf("===== FAIL - Error from BIO_new_file\n");
        printf("==========================================\n");
        result = -1;
    }

    if (result == 0) {
        printf("===== Read certificate from %s\n", certificateFilename);

        certificate = X509_new();
        if (PEM_read_bio_X509(bio_in, &certificate, 0, NULL) == NULL) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from PEM_read_bio_X509\n");
            printf("==========================================\n");
            result = -1;
        }
    }

    if (result == 0) {
        pubKey = X509_get_pubkey(certificate);
        if (pubKey == NULL) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from X509_get_pubkey\n");
            printf("==========================================\n");
            EVP_PKEY_CTX_free(ctx);
            result = -1;
        }
    }

    if (result == 0) {
        eckey_pub = EVP_PKEY_get1_EC_KEY(pubKey);
        if (eckey_pub == NULL) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from EVP_PKEY_get1_EC_KEY\n");
            printf("==========================================\n");
            EVP_PKEY_CTX_free(ctx);
            result = -1;
        }
    }
    free(pubKey);

    if (result == 0) {
        res = ECDSA_do_verify(&indata[0], inlen, ecdsa_sig, eckey_pub);
        if(res == 1) {
            result = 0;
        } else if (res == -1) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from ECDSA_do_verify\n");
            printf("==========================================\n");
            EVP_PKEY_CTX_free(ctx);
            result = -1;
        } else {
            printf("===== Signature Verification Failure\n");
            result = -1;
        }
    }
    return result;
}
