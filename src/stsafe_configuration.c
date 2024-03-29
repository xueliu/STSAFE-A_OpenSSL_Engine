/**
 *********************************************************************************************
 * @file    stsafe_a_configuration.c
 * @author  SMD application team
 * @version V1.0.1
 * @date    10-July-2020
 * @brief   STSAFE-A tools command.
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
#include <stdlib.h>
#include <string.h>

#include "stsafea_types.h"
#include "stsafea_core.h"
#include "stsafea_conf.h"
#include "stsafea_crypto.h"
#include "stsafea_interface_conf.h"
#include "stsafea_service.h"
#include "openssl/crypto.h"
#include "engine_debug.h"

extern STSAFEA_HW_t HwCtx;

/* Private typedef -----------------------------------------------------------*/

/* Private defines -----------------------------------------------------------*/
#define CRC_SUPPORT                 1     /* Crc support flag */

/* Private macros ------------------------------------------------------------*/


/* Private variables ---------------------------------------------------------*/


//global inout buffer
static uint8_t ExchangeMemory[STSAFEA_BUFFER_MAX_SIZE + 12];
/* Global variables ----------------------------------------------------------*/

/* Private function prototypes -----------------------------------------------*/

/* Functions Definition ------------------------------------------------------*/

/*****************************/
/* Create handle             */
/*****************************/
StSafeA_ResponseCode_t StSafeA_CreateHandle(
  StSafeA_Handle_t *pStSafeA)
{
    StSafeA_ResponseCode_t status_code = STSAFEA_OK;

    StSafeA_Init(pStSafeA, (uint8_t *)ExchangeMemory);
    DEBUG_PRINTF("STSAFE-A110 StSafeA_CreateHandle = %d, pStSafeA->InOutBuffer = %p, pStSafeA->InOutBuffer.LV.Data = %p\n",status_code, &pStSafeA->InOutBuffer, pStSafeA->InOutBuffer.LV.Data);

    /* Initialize all configured peripherals */
    //if (StSafeA_Bus_Init() == 0)
   // {
   //   status_code = STSAFEA_OK;
   // }

    return status_code;
}

/*****************************/
/* Get CRC support           */
/*****************************/
uint8_t StSafeA_GetCRCsupport(
  void* handle)
{
  uint8_t crc_support = 0;

  if (handle != NULL)
  {
   StSafeA_Handle_t *pStSafeA = handle;

    crc_support = pStSafeA->CrcSupport;
  }

  return crc_support;
}

/*****************************/
/* Set CRC support           */
/*****************************/
uint8_t StSafeA_SetCRCsupport(
  void* handle,
  uint8_t in_crc_support)
{
  uint8_t crc_support = 0;

  if (handle != NULL)
  {
    StSafeA_Handle_t *pStSafeA = handle;

    pStSafeA->CrcSupport = in_crc_support;
    crc_support = StSafeA_GetCRCsupport(handle);
  }

  return crc_support;
}

/************************/
/* Get Data buffer size */
/************************/
uint16_t StSafeA_GetDataBufferSize(void)
{
  return STSAFEA_BUFFER_MAX_SIZE;
}


#ifdef STSAFE_A_SIGN_SESSION

/************************/
/* Get Hash Type        */
/************************/
StSafeA_HashTypes_t StSafeA_GetHashType(void* handle)
{
  StSafeA_HashTypes_t hash_type = STSAFEA_SHA_256;

  if (handle != NULL)
  {
    StSafeA_Handle_t *pStSafeA = handle;

    hash_type = pStSafeA->HashObj.HashType;
  }

  return hash_type;
}

/************************/
/* Get Hash             */
/************************/
uint8_t* StSafeA_GetHashBuffer(void* handle)
{
  uint8_t* hash_buffer = NULL;

  if (handle != NULL)
  {
    StSafeA_Handle_t *pStSafeA = handle;

    hash_buffer = &pStSafeA->HashObj.HashRes[0];
  }

  return hash_buffer;
}

#endif /* STSAFE_A_SIGN_SESSION */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
