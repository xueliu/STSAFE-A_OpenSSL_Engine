/**
 *********************************************************************************************
 * @file    stsafe_rand.c
 * @author  SMD application team
 * @version V1.0.0
 * @date    26-June-2019
 * @brief   Openssl STSAFE Engine Random function 
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

#include <string.h>
#include <openssl/ossl_typ.h>
#include <openssl/engine.h>
#include "stsafea_types.h"
#include "stsafea_core.h"
#include "stsafea_conf.h"
#include "stsafea_service.h"
#include "stsafe_init.h"
#include "engine_debug.h"

int stsafe_random_status(void)
{
    return 1;
}

int stsafe_get_random_bytes(unsigned char *buffer, int num)
{
    StSafeA_LVBuffer_t  Response   = { 0 };
    uint32_t            StatusCode = 0;
    long int            opensslerr = 0;
    char                opensslerrbuff[1024];

    StSafeA_Handle_t   *pStSafeA   = &stsafea_handle;

    memset(opensslerrbuff, 0x00, 1024 * sizeof(char));

    DEBUG_PRINTF("Stsafe engine random length %d\n", num);

    Response.Data = (uint8_t *) OPENSSL_malloc(STSAFEA_BUFFER_MAX_SIZE * sizeof(uint8_t));
    if(Response.Data == NULL) {
        opensslerr = ERR_get_error();
        DEBUG_PRINTF("STSAFE> %s: OPENSSL_malloc failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            DEBUG_PRINTF("STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        StatusCode = STSAFEA_INVALID_PARAMETER;
    }

    if (StatusCode == STSAFEA_OK) {
        Response.Length = STSAFEA_BUFFER_MAX_SIZE;

        StatusCode = StSafeA_GenerateRandom(pStSafeA, STSAFEA_EPHEMERAL_RND, num, &Response, STSAFEA_MAC_NONE);
        if(StatusCode == 0) {
            DEBUG_PRINTF("\nSTSAFE> %s:  Success Random number = 0x", __func__);
            for(int i = 0; i < num; i++) {
                DEBUG_PRINTF("%02x",*((Response.Data)+i));
            }
            DEBUG_PRINTF("\n");
            memcpy(buffer, Response.Data, num);
        }
        OPENSSL_free(Response.Data);
    }

    if (StatusCode == 0)
        return ENGINE_OPENSSL_SUCCESS;
    else
        return ENGINE_OPENSSL_FAILURE;
}

RAND_METHOD stsafe_random_method = {
        NULL,                       /* seed */
        stsafe_get_random_bytes,    /*bytes*/
        NULL,                       /* cleanup */
        NULL,                       /* add */
        NULL,                       /*Pseduorand*/
        stsafe_random_status        /*Status*/      
};
