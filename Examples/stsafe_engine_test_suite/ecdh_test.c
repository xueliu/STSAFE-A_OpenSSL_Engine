/**
 *********************************************************************************************
 * @file    ecdh_test.c
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

extern int32_t ecdh_test(void)
{
    int32_t   result      = 0;
    EC_KEY   *ecdh        = NULL;
    EC_KEY   *eckey3      = NULL;
    EC_GROUP *ec_group3   = NULL;
    int       keylen      = 0;
    long int  opensslerr  = 0;
    char      opensslerrbuff[1024];
    unsigned char agreed_value[200];

    const EC_POINT *pubkey      = NULL;

    memset(opensslerrbuff, 0x00, 1024 * sizeof(char));

    printf("===== Setup for test\n");

    ecdh = EC_KEY_new();
    if (ecdh == NULL) {
        opensslerr = ERR_get_error();
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
        }
        printf("===== FAIL - Error from EC_KEY_new\n");
        printf("==========================================\n");
        result = -1;
    }

    if (result == 0) {
        if ((ec_group3 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
            result = -1;
            goto handleError;
        }
        if ((eckey3 = EC_KEY_new()) == NULL) {
            result = -1;
            goto handleError;
        }
        if (EC_KEY_set_group(eckey3, ec_group3) == 0) {
            result = -1;
            goto handleError;
        }
        if (EC_KEY_set_group(ecdh, ec_group3) == 0) {
            result = -1;
            goto handleError;
        }
        if (EC_KEY_generate_key(eckey3) == 0)  {
            result = -1;
            goto handleError;
        }
        if ((pubkey = EC_KEY_get0_public_key(eckey3)) == NULL) {
            result = -1;
            goto handleError;
        }

        if (EC_KEY_generate_key(ecdh) == 0)  {
            result = -1;
            goto handleError;
        }
handleError:
        if (result == -1) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from OpenSSL\n");
            printf("==========================================\n");
            result = -1;
        }
    }

    if (result == 0) {
        if( (pubkey != NULL) && (ecdh != NULL) ) {
            keylen = ECDH_compute_key(agreed_value, 200, pubkey, ecdh, NULL);
            if (keylen == -1) {
                opensslerr = ERR_get_error();
                if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                    printf("===== OpenSSL error %ld %s", opensslerr, opensslerrbuff);
                }
                printf("===== FAIL - Error from ECDH_compute_key\n");
                printf("==========================================\n");
                result = -1;
            }
        }
    }
    return result;
}


