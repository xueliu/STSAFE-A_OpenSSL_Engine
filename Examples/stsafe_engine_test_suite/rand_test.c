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
