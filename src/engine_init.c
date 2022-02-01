/**
 *********************************************************************************************
 * @file    engine_c.c
 * @author  SMD application team
 * @version V1.0.1
 * @date    08-july-2020
 * @brief   Openssl STSAFE Engine Main for bind and entry point
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

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>

#include "stsafeaxxx.h"
#include "stsafe_init.h"
#include "stsafe_api.h"
#include "stsafe_a_configuration.h"

#define STSAFE_ENGINE_PKEY_SUPPORT 1

/**
 * @brief engine_stsafe_id
 */
static const char *engine_stsafe_id = "Stsafe";

/**
 * @brief engine_stsafe_name
 */
static const char *engine_stsafe_name = "STSAFE-A110 engine for OpenSSL";

/**
 * @brief stsafe_slot
 */
long int stsafe_sig_key_slot  = STSAFEA_KEY_SLOT_0;
long int stsafe_gen_key_slot  = STSAFEA_KEY_SLOT_EPHEMERAL;
long int stsafe_memory_region = 0;

static int engine_finish(ENGINE *e)
{

    (void)e;
    
    return 1;

}

/** OpenSSL's method to bind an engine.
 *
 * Initializes the name, id and function pointers of the engine.
 * @brief bind_helper
 * @param e The STSAFE engine to initialize
 * @param id The identifier of the engine
 * @retval 0 if binding failed
 * @retval 1 on success
 */
static int
bind_helper(ENGINE *e, const char *id)
{
    int ret = 0;

    fprintf(stdout, "ENGINE> %s: Engine id = %s\n", __func__, id);
    if (id && (strcmp(id, engine_stsafe_id) != 0)) {
        fprintf(stderr, "ENGINE> %s: Engine id lookup failed\n", __func__);
        return ENGINE_OPENSSL_FAILURE;
    }


    if (!ENGINE_set_id(e, engine_stsafe_id)) {
        fprintf(stderr, "ENGINE> %s: ENGINE_set_id failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_id completed\n", __func__);

    if (!ENGINE_set_name(e, engine_stsafe_name)) {
        fprintf(stderr, "ENGINE> %s: ENGINE_set_name failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_name completed\n", __func__);

    if (!ENGINE_set_init_function(e, stsafe_init)){
        fprintf(stderr, "ENGINE> %s: ENGINE_set_init_function failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_init_function completed\n", __func__);

    if (!ENGINE_set_RAND(e, &stsafe_random_method)){
        fprintf(stderr, "ENGINE> %s: ENGINE_set_RAND failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_RAND completed\n", __func__);

    if (!ENGINE_set_ctrl_function(e, stsafe_cmd_ctrl)){
        fprintf(stderr, "ENGINE> %s: ENGINE_set_ctrl_function failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_ctrl_function completed\n", __func__);

    if (!ENGINE_set_cmd_defns(e, stsafe_cmd_defns)){
        fprintf(stderr, "ENGINE> %s: ENGINE_set_cmd_defns failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_cmd_defns completed\n", __func__);

    if (!ENGINE_set_EC(e, stsafe_get_EC_methods())){
        fprintf(stderr, "ENGINE> %s: ENGINE_set_EC failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_EC completed\n", __func__);

#if STSAFE_ENGINE_PKEY_SUPPORT
    if (!ENGINE_set_load_pubkey_function(e, stsafe_load_pubkey)){
        fprintf(stderr, "ENGINE> %s: ENGINE_set_load_pubkey_function failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_load_pubkey_function completed\n", __func__);

    if (!ENGINE_set_load_privkey_function(e, stsafe_load_privkey)){
        fprintf(stderr, "ENGINE> %s: ENGINE_set_load_privkey_function failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_load_privkey_function completed\n", __func__);

    if(!stsafe_pkey_meth_init()){
        fprintf(stderr, "ENGINE> %s: stsafe_pkey_meth_init failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: stsafe_pkey_meth_init completed\n", __func__);

    if (! ENGINE_set_pkey_meths(e, stsafe_pkey_meths)){
        fprintf(stderr, "ENGINE> %s: ENGINE_set_pkey_meths failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_pkey_meths completed\n", __func__);

#endif 

    fprintf(stdout, "ENGINE> %s: calling Engine_set_finish_function\n", __func__);
    if (!ENGINE_set_finish_function(e, engine_finish)) {
        fprintf(stderr, "ENGINE> %s: ENGINE_set_finish_function failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_finish_function completed\n", __func__);

    fprintf(stdout, "ENGINE> %s: calling ENGINE_set_default\n", __func__);
    if (!ENGINE_set_default(e, (ENGINE_METHOD_DH | ENGINE_METHOD_RAND | ENGINE_METHOD_CIPHERS |
                                ENGINE_METHOD_DIGESTS | ENGINE_METHOD_PKEY_METHS |
                                ENGINE_METHOD_EC) )) {
        fprintf(stderr, "ENGINE> %s: ENGINE_set_default failed\n", __func__);
        goto end;
    }
    fprintf(stdout, "ENGINE> %s: ENGINE_set_default completed\n", __func__);

    ret = 1;
end:
    return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
IMPLEMENT_DYNAMIC_CHECK_FN()

static ENGINE* ENGINE_stsafe(void)
{
    fprintf(stdout, "ENGINE> %s:\n", __func__);
    ENGINE *eng = ENGINE_new();

    if (!eng) {
        return NULL;
    }
    fprintf(stdout, "Before calling bind_helper.");
    if (!bind_helper(eng, engine_stsafe_id)) {
        
        fprintf(stdout, "After failed calling bind_helper.");
        
        ENGINE_free(eng);
        return NULL;
    }

    fprintf(stdout, "After calling bind_helper.");

    return eng;
}

void ENGINE_load_stsafe(void)
{
    fprintf(stdout, "ENGINE> %s:\n", __func__);
    ENGINE *toadd = ENGINE_stsafe();
    if (!toadd) {
        fprintf(stderr, "STSAFE> %s: Engine failed to load\n", __func__);
        return;
    }
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

