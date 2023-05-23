/**
 *********************************************************************************************
 * @file    query_test.c
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

#include <openssl/engine.h>

#include <stsafe_api.h>

#include "test_stsafe_engine.h"

/* private data */
typedef enum QueryIdx_e
{
    DataPartitionQuery,
    ProductDataQuery,
    I2cParameterQuery,
    LifeCycleStateQuery,
    HostKeySlotQuery,
    LocalEnvelopeKeySlotQuery,
    PublicKeySlotQuery,
    CommandAuthorizationConfigurationQuery,
    EndQueryList
} QueryIdx_t;

static const char *QueryStr[EndQueryList] =
{
    "DataPartition",
    "ProductData",
    "I2cParameter",
    "LifeCycleState",
    "HostKeySlot",
    "LocalEnvelopeKeySlot",
    "PublicKeySlot",
    "CommandAuthorizationConfiguration"
};

extern int32_t query_test(void)
{
    int32_t   result      = 0;
    long int  opensslerr  = 0;
    char      opensslerrbuff[1024];

    memset(opensslerrbuff, 0x00, 1024 * sizeof(char));

    for (int i = 0; i < EndQueryList; i++) {
        printf("===== Query %s\n", QueryStr[i]);
        if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_QUERY, 0, (void *)QueryStr[i], 0)) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("==========================================\n");
            printf("===== FAIL - Error from ENGINE_ctrl\n");
            printf("==========================================\n");
            result = -1;
            break;
        }
    }

    return result;
}
