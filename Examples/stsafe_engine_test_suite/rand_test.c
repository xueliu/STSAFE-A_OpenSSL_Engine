/**
 *********************************************************************************************
 * @file    rand_test.c
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
#include <stdint.h>
#include <string.h>

#include <openssl/engine.h>

#include "test_stsafe_engine.h"

#define RAND_BUF_SIZE 5

extern int32_t rand_test(void)
{
    int32_t   result     = 0;
    int       res        = 0;
    long int  opensslerr = 0;

    char          opensslerrbuff[1024];
    unsigned char rand_buf[RAND_BUF_SIZE] = { 0 };

    memset(opensslerrbuff, 0x00, 1024 * sizeof(char));

    /*Setting the Stsafe engine random function as default openssl rand method */
    if (!ENGINE_set_default_RAND(stsafe_engine)) {
        opensslerr = ERR_get_error();
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
        }
        printf("===== FAIL - Error from ENGINE_set_default_RAND\n");
        printf("==========================================\n");
        result = -1;
    }

    if (result == 0) {
        res = RAND_bytes(rand_buf, RAND_BUF_SIZE);

        if (res == 1) {
            result = 0;
        } else if (res == 0) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from RAND_bytes\n");
            printf("==========================================\n");
            result = -1;
        } else {
            printf("===== FAIL - RAND not supported\n");
            printf("==========================================\n");
        }
    }

    return result;
}
