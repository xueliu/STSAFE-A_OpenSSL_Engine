/**
 *********************************************************************************************
 * @file    stsafe_init.c
 * @author  SMD application team
 * @version V1.0.1
 * @date    31-July-2020
 * @brief   Openssl STSAFE Engine init and command ctrl functions
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
/* Includes ------------------------------------------------------------------*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include "openssl/bn.h"
#include "openssl/sha.h"
#include "openssl/pem.h"
#include "openssl/opensslv.h"

#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#include <openssl/rand.h>
#include "openssl/ossl_typ.h"

#include "stsafe_init.h"
#include "stsafe_api.h"
#include "stsafea_types.h"
#include "stsafea_core.h"
#include "stsafea_conf.h"
#include "stsafea_crypto.h"
#include "stsafea_service.h"
#include "stsafea_interface_conf.h"
#include "stsafe_a_configuration.h"

#define STS_CHK(ret, f)                     if ((ret) == 0) { ret = f; }

int32_t stsafe_pairing(void);

int32_t StSafeA_HostKeys_Program(StSafeA_Handle_t *p);

StSafeA_Handle_t stsafea_handle;
static uint8_t stsafe_serial[9];
static uint8_t cmd_auth[STSAFEA_MAX_CMD][2];

int32_t get_cmd_auth_enc(uint8_t cmd, uint8_t *mac, uint8_t *enc)
{
    if ((mac == NULL) || (enc == NULL))
        return -1;
    if (cmd < STSAFEA_MAX_CMD)
    {
        *mac = cmd_auth[cmd][0];
        *enc = cmd_auth[cmd][1];
        return 0;
    }
    return -1;
}


/* Developer host pairing keys. Do NOT use in a product. */

uint8_t *stsafe_get_serial(void)
{
  return stsafe_serial;
}

/**
  * @brief   stsafe_init
  *          Initialize STSAFE-A1xx Driver. Create driver handle, 
  * @note    This is a real function that MUST be implemented at application interface level.
  *          A specific example template stsafea_crypto_xxx_interface_template.c is provided with this Middleware.
  *
  * @param   None
  * @retval  0 if success. An error code otherwise.
  */
int stsafe_init(struct engine_st *ctx)
{
    (void)ctx;
    uint8_t status_code = 1;
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;

    DEBUG_PRINTF("Using Openssl     : %s\n", SSLeay_version(SSLEAY_VERSION));

    /* Create STSAFE-A's handle */
    status_code = StSafeA_CreateHandle(pStSafeA);

    if (status_code == 0)
    {
        DEBUG_PRINTF("StSafeA_GetDataBufferSize(): %d\n", StSafeA_GetDataBufferSize());
    
        status_code = stsafe_pairing();
        if (status_code == 0)
        {
            DEBUG_PRINTF("Main : stsafe_pairing success \n");
        }
   
        DEBUG_PRINTF("\n************^^^^^^^^^^^^*************** \n");       
        DEBUG_PRINTF("Setting STSAFE-A110 host keys\n");

        /* Initialize/Retrieve the Host MAC and Cipher Keys  */
        if (StSafeA_HostKeys_Init() == 0)
        {
            status_code = STSAFEA_OK;
        }

    }
    StSafeA_ProductDataBuffer_t query_d;
    memset(&query_d, 0, sizeof(StSafeA_ProductDataBuffer_t));
    StSafeA_ProductDataBuffer_t *query = &query_d;
    status_code = StSafeA_ProductDataQuery(pStSafeA,
                                          query,
                                          STSAFEA_MAC_NONE);
    if ((status_code == 0) && (query != NULL)) {
      memcpy(stsafe_serial, query->STNumber, 9);
    }
    StSafeA_CommandAuthorizationRecordBuffer_t cmd_rec[STSAFEA_MAX_CMD];
    StSafeA_CommandAuthorizationConfigurationBuffer_t cmd_auth_enc;

    cmd_auth_enc.pCommandAuthorizationRecord = cmd_rec;


    status_code = StSafeA_CommandAuthorizationConfigurationQuery(pStSafeA, STSAFEA_MAX_CMD, &cmd_auth_enc, STSAFEA_MAC_NONE);
    if (status_code == 0)
    {
        for (int i = 0; i < cmd_auth_enc.CommandAuthorizationRecordNumber; i++)
        {
            uint8_t l_index = STSAFEA_MAX_CMD+1;
            switch(cmd_rec[i].CommandCode)
            {
                case 0x1C : l_index = STSAFEA_DECRYPT; break;
                case 0x08 : l_index = STSAFEA_DERIVE; break;
                case 0x1B : l_index = STSAFEA_ENCRYPT; break;
                case 0x18 : l_index = STSAFEA_ESTABLISH; break;
                case 0x09 : l_index = STSAFEA_GEN_MAC; break;
                case 0x16 : l_index = STSAFEA_GEN_SIG; break;
                case 0x0f : l_index = STSAFEA_UNWRAP; break;
                case 0x0E : l_index = STSAFEA_WRAP; break;
                case 0x0A : l_index = STSAFEA_VER_MAC; break;
            }
            if (l_index < STSAFEA_MAX_CMD)
            {
                cmd_auth[l_index][0] = (cmd_rec[i].CommandAC == 1 ? STSAFEA_MAC_NONE : STSAFEA_MAC_HOST_CMAC);
                cmd_auth[l_index][1] = (cmd_rec[i].HostEncryptionFlags);
            }
        }
    }
    DEBUG_PRINTF("\n************vvvvvvvvvvvv*************** \n");

    return ENGINE_OPENSSL_SUCCESS;
}

/**
  * @brief   stsafe_pairing
  *          This function pairs host with STSAFE-A110 using pairing keys(host & MAC) and sets up the LocalEnvelope key slots.
  *
  * @param   None
  * @retval  0 if success. An error code otherwise.
  */
int32_t stsafe_pairing(void)
{
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    int32_t StatusCode = 0;
    StSafeA_HostKeySlotBuffer_t HostKeySlot;
   
    /* This code checks and generates the LocalEnvelope keys (Slots 0,1) for Wrap and Unwrap functions.
       These key slots can only be set once */
    StSafeA_LocalEnvelopeKeyTableBuffer_t *LocalEnvelopeKeyTable = (StSafeA_LocalEnvelopeKeyTableBuffer_t *)malloc(sizeof(StSafeA_LocalEnvelopeKeyTableBuffer_t));
    StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t  *LocalEnvelopeInfoSlot0 = (StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t *)malloc(sizeof(StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t));   
    StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t  *LocalEnvelopeInfoSlot1 = (StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t *)malloc(sizeof(StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t));
    DEBUG_PRINTF("About to call StSafeA_LocalEnvelopeKeySlotQuery: %p, %p, %p \n", LocalEnvelopeKeyTable, LocalEnvelopeInfoSlot0, LocalEnvelopeInfoSlot1 );

    /* Check if the LocalEnveope key slots are populated */
    StatusCode = StSafeA_LocalEnvelopeKeySlotQuery(pStSafeA, LocalEnvelopeKeyTable, LocalEnvelopeInfoSlot0, LocalEnvelopeInfoSlot1, STSAFEA_MAC_NONE);

    DEBUG_PRINTF("StSafeA_LocalEnvelopeKeySlotQuery: %d slot 0: presence flag =%d \n", StatusCode,LocalEnvelopeInfoSlot0->PresenceFlag );
    if ((StatusCode == 0) && (LocalEnvelopeInfoSlot0->PresenceFlag == 0))
    {
        DEBUG_PRINTF("Calling StSafeA_GenerateLocalEnvelopeKey\n" );
        StatusCode = StSafeA_GenerateLocalEnvelopeKey(pStSafeA, STSAFEA_KEY_SLOT_0, STSAFEA_KEY_TYPE_AES_128, NULL, 0, STSAFEA_MAC_NONE);
        DEBUG_PRINTF(" StSafeA_GenerateLocalEnvelopeKey StatusCode =%d\n",StatusCode );
    }

    DEBUG_PRINTF("StSafeA_LocalEnvelopeKeySlotQuery: %d slot 1: presence flag =%d \n", StatusCode,LocalEnvelopeInfoSlot1->PresenceFlag );
    if ((StatusCode == 0) && (LocalEnvelopeInfoSlot1->PresenceFlag == 0))
    {
        DEBUG_PRINTF("Calling StSafeA_GenerateLocalEnvelopeKey\n" );     
        StatusCode = StSafeA_GenerateLocalEnvelopeKey(pStSafeA, STSAFEA_KEY_SLOT_1, STSAFEA_KEY_TYPE_AES_128, NULL, 0, STSAFEA_MAC_NONE);
        DEBUG_PRINTF(" StSafeA_GenerateLocalEnvelopeKey StatusCode =%d\n",StatusCode );     
    }

    /* Host key pairing */
    DEBUG_PRINTF("---HostKeySlot = %p, pStSafeA->InOutBuffer.LV.Data = %p\n", &HostKeySlot, pStSafeA->InOutBuffer.LV.Data);
  
    /* Check if host cipher key & host MAC key are populated if not then they are populated */
    StatusCode =  StSafeA_HostKeySlotQuery(pStSafeA, &HostKeySlot, STSAFEA_MAC_NONE);
    DEBUG_PRINTF("HostKeySlot->HostKeyPresenceFlag: %d \n", HostKeySlot.HostKeyPresenceFlag  );     

    pStSafeA->HostMacSequenceCounter = HostKeySlot.HostCMacSequenceCounter;

    /* If the host keys are not popluated then popululate them with the static development keys.
       These key slots can only be set once.
       NOTE: For products random key values should be used */
    if (!HostKeySlot.HostKeyPresenceFlag)      
    {
        StSafeA_HostKeys_Program(pStSafeA);
    }
    free(LocalEnvelopeKeyTable);
    free(LocalEnvelopeInfoSlot0);
    free(LocalEnvelopeInfoSlot1);
     
    return  StatusCode ;
}

int stsafe_shutdown(void)
{
    return 0;
}

int stsafe_reset(void)
{
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    
    DEBUG_FPRINTF(stdout, "ENGINE> %s: Reseting STSAFE hardware to default state, and then re-init the driver.\n", __func__);
    StSafeA_Reset(pStSafeA, STSAFEA_MAC_NONE);
    stsafe_init(NULL);
    
    return 0;
    
}

int stsafe_hibernate(int wakeupcode)
{
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    int32_t StatusCode = 0;

    DEBUG_FPRINTF(stdout, "ENGINE> %s: Reseting STSAFE hardware to default state, and then re-init the driver.\n", __func__);
    StatusCode = StSafeA_Hibernate(pStSafeA, wakeupcode, STSAFEA_MAC_NONE);

    return StatusCode;
}
