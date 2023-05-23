/**
 *********************************************************************************************
 * @file    ecdsa_sign_verify.c
 * @author  SMD application team
 * @version V1.0.0
 * @date    23-July-2020
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

static const char *certificateFilename = "Device-Cert.pem";

extern int32_t ecdsa_test(void)
{
    int32_t    result      = 0;
    uint8_t    Hash[32]    = { 0 };
    uint32_t   HashSize    = 0;
    EC_KEY    *eckey       = NULL;
    ECDSA_SIG *signature   = NULL;
    BIO       *bio_in      = NULL;
    X509      *certificate = NULL;
    EVP_PKEY  *pubKey      = NULL;
    EC_KEY    *eckey_pub   = NULL;
    long int   opensslerr  = 0;
    char       opensslerrbuff[1024];

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
        printf("===== Generate digest\n");
        GenerateUnsignedChallenge(sizeof(Hash), &Hash[0]);

        if (0 == EVP_Digest(Hash, 32, &Hash[0], &HashSize, EVP_sha256(), NULL)) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from EVP_Digest\n");
            printf("==========================================\n");
            result = -1;
        }

        if (result == 0) {
            printf("===== ECDSA sign\n");

            // Set the slot
            if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_SET_GEN_KEY_SLOT, 0, NULL, NULL)) {
              opensslerr = ERR_get_error();
              printf("STSAFEKEYGEN> %s: ENGINE_ctrl could not slet Slot %d failed\n", __func__, 0);
              if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
              }
              result = -1;
            }
            eckey  = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            if (eckey == NULL) {
              opensslerr = ERR_get_error();
              printf("STSAFEKEYGEN> %s: EC_KEY_new_by_curve_name failed\n", __func__);
              if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
              }
              result = -1;
            }
#if 0
            eckey = EC_KEY_new();
            if (eckey == NULL) {
                opensslerr = ERR_get_error();
                if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                    printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
                }
                printf("===== FAIL - Error from EC_KEY_new\n");
                printf("==========================================\n");
                result = -1;
            }
#endif
            if (! (EC_KEY_generate_key(eckey))) {
              opensslerr = ERR_get_error();
              printf("STSAFEKEYGEN> %s: EC_KEY_generate_key failed\n", __func__);
              if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
              }
              result = -1;
            }
            if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_SET_GEN_KEY_SLOT, 255, NULL, NULL)) {
              opensslerr = ERR_get_error();
              printf("STSAFEKEYGEN> %s: ENGINE_ctrl could not slet Slot %d failed\n", __func__, 255);
              if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
              }
              result = -1;
            }
        }
    }

    if (result == 0) {
        printf("\n");
        signature = ECDSA_do_sign(Hash,32, eckey);
        if (signature == NULL) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from ECDSA_do_sign\n");
            printf("==========================================\n");
            result = -1;
        }
    }

    if (result == 0) {
        printf("===== ECDSA Verify Process\n");
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
        printf("===== Get public key from certificate\n");

        pubKey = X509_get_pubkey(certificate);
        if (pubKey == NULL) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from X509_get_pubkey\n");
            printf("==========================================\n");
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
            result = -1;
        }
    }
    free(pubKey);

    if (result == 0) {
        printf("===== Do verification\n");
        result = ECDSA_do_verify(&Hash[0], HashSize, signature, eckey_pub);

        if(result == 1) {
            printf("===== Verification Success\n");
            result = 0;
        } else {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from ECDSA_do_verify\n");
            printf("==========================================\n");
            result = -1;
        }
    }
    return result;
}

