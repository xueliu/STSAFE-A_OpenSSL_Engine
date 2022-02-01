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
 * SLA0088 SOFTWARE LICENSE AGREEMENT
 * Revision : 2
 * Date : 28-Oct-2020
 *
 * BY INSTALLING, COPYING, DOWNLOADING, ACCESSING OR OTHERWISE USING THIS SOFTWARE OR ANY PART
 * THEREOF (AND THE RELATED DOCUMENTATION) FROM STMICROELECTRONICS INTERNATIONAL N.V, SWISS
 * BRANCH AND/OR ITS AFFILIATED COMPANIES (STMICROELECTRONICS), THE RECIPIENT, ON BEHALF OF HIMSELF
 * OR HERSELF, OR ON BEHALF OF ANY ENTITY BY WHICH SUCH RECIPIENT IS EMPLOYED AND/OR ENGAGED
 * AGREES TO BE BOUND BY THIS SOFTWARE LICENSE AGREEMENT.
 * Under STMicroelectronics’ intellectual property rights, the redistribution, reproduction and use in source and binary forms of the
 * software or any part thereof, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistribution of source code (modified or not) must retain any copyright notice, this list of conditions and the disclaimer
 *    set forth below as items 11 and 12.
 * 2. Redistributions in binary form, except as embedded into a microcontroller or microprocessor device or a software update
 *    for such device, must reproduce any copyright notice provided with the binary code, this list of conditions, and the
 * disclaimer set forth below as items 11 and 12, in documentation and/or other materials provided with the distribution.
 * 3. Neither the name of STMicroelectronics nor the names of other contributors to this software may be used to endorse or
 *    promote products derived from this software or part thereof without specific written permission.
 * 4. This software or any part thereof, including modifications and/or derivative works of this software, must be used and
 *    execute solely and exclusively on or in combination with a secure microcontroller device manufactured by or for
 * STMicroelectronics.
 * 5. No use, reproduction or redistribution of this software partially or totally may be done in any manner that would subject this
 *    software to any Open Source Terms. “Open Source Terms” shall mean any open source license which requires as part of
 *    distribution of software that the source code of such software is distributed therewith or otherwise made available, or open
 *    source license that substantially complies with the Open Source definition specified at www.opensource.org and any other
 *    comparable open source license such as for example GNU General Public License (GPL), Eclipse Public License (EPL),
 *    Apache Software License, BSD license or MIT license.
 * 6. STMicroelectronics has no obligation to provide any maintenance, support or updates for the software.
 * 7. The software is and will remain the exclusive property of STMicroelectronics and its licensors. The recipient will not take
 *    any action that jeopardizes STMicroelectronics and its licensors' proprietary rights or acquire any rights in the software,
 *    except the limited rights specified hereunder.
 * 8. The recipient shall comply with all applicable laws and regulations affecting the use of the software or any part thereof
 *    including any applicable export control law or regulation.
 * 9. Redistribution and use of this software or any part thereof other than as permitted under this license is void and will
 *    automatically terminate your rights under this license.
 * 10. Anti-Bribery; Anti-Corruption. The recipient shall not violate, or permit any third party to violate, any applicable anti-bribery
 *     or anti-corruption law, or STMicroelectronics’ Code of Conduct that is available on www.st.com. In the event of a violation,
 *     the recipient shall notify STMicroelectronics and STMicroelectronics may terminate this Agreement.
 * 11. THIS SOFTWARE IS PROVIDED BY STMICROELECTRONICS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS,
 *     IMPLIED OR STATUTORY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *     MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT OF THIRD PARTY
 *     INTELLECTUAL PROPERTY RIGHTS, WHICH ARE DISCLAIMED TO THE FULLEST EXTENT PERMITTED BY LAW.
 *     IN NO EVENT SHALL STMICROELECTRONICS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *     INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *     PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *     INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *     LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *     SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 12. EXCEPT AS EXPRESSLY PERMITTED HEREUNDER, NO LICENSE OR OTHER RIGHTS, WHETHER EXPRESS
 *     OR IMPLIED, ARE GRANTED UNDER ANY PATENT OR OTHER INTELLECTUAL PROPERTY RIGHTS OF
 *     STMICROELECTRONICS OR ANY THIRD PARTY.
 ******************************************************************************
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

