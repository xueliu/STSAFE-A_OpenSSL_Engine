/**
 *********************************************************************************************
 * @file    stsafe_init.h
 * @author  
 * @version V1.0.0
 * @date    31/7/2020
 * @brief   stsafe init file.
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
#ifndef STSAFE_API_H
#define STSAFE_API_H

/* Includes ------------------------------------------------------------------*/
#include <stdint.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/sha.h"
#include "openssl/pem.h"
#include "openssl/opensslv.h"
#include "openssl/x509.h"

/* OpenSSL return types don't seem to have a define but since they are counter
    to the convention of cryptoauthlib they are defined here */
#define ENGINE_OPENSSL_SUCCESS                  (1)
#define ENGINE_OPENSSL_FAILURE                  (0)
#define ENGINE_OPENSSL_ERROR                    (-1)

/* The CMD number for the Ctrl function */
typedef enum {
    STSAFE_CMD_GET_PRODUCT_DATA = ENGINE_CMD_BASE,
    STSAFE_CMD_GET_DEVICE_CERT,
    STSAFE_CMD_SET_SIG_KEY_SLOT,
    STSAFE_CMD_SET_GEN_KEY_SLOT,
    STSAFE_CMD_SET_MEMORY_REGION,
    STSAFE_CMD_WRITE_DEVICE_CERT,
    STSAFE_CMD_RESET,
    STSAFE_CMD_ECHO,
    STSAFE_CMD_HIBERNATE,
    STSAFE_CMD_VERIFYPASSWORD,
    STSAFE_CMD_QUERY,
    STSAFE_CMD_MAX
} STSAFE_CMD_LIST;

/* APIs -----------------------------------------------------------------------*/

/** 
 *  
 * name:    Call the engine to load the Stsafe
 *
 * param    None
 * retval   None.
 * 
 * */
void ENGINE_load_stsafe(void);

/* Administration */
/**
  * name:    Initialize the driver
  *
  * param    None
  * retval   0 if success. An error code otherwise.
 *   
 */
int stsafe_init(ENGINE *e);

/** 
 * name:    Reset the StSafe and call the initialization 
 *
 * param    None
 * retval   0 if success. An error code otherwise.
 */
int stsafe_reset(void);

/** 
 *   
 * name:    Put the hardware in hibernate mode
 *
 * param    None
 * retval   0 if success. An error code otherwise.
 */
int stsafe_hibernate(int wakeupcode);

/**
  * name:   stsafe_password_verification
  *          This command performs password verification
  *          and remembers the outcome of the verification for future command authorization.
  *
  * param   pInPassword         : Pointer to password bytes array (should be 16 bytes length).
  * param   response            : placeholder of the result, should be 2 bytes long, should be pre-allocated by the caller.\n
  * retval  0 if success, 1 otherwise.
  */
uint32_t stsafe_password_verification(const uint8_t *pInPassword, uint8_t *response);


/**
  * name:    stsafe_pairing
  *          This function pairs host with STSAFE-A110 using pairing keys and sets up the LOcal Evelope keys for Wrap and Unwrap.
  *
  * param    None
  * retval   0 if success. An error code otherwise.
  */
int32_t stsafe_pairing(void);

/* function call for the CMD listed in STSAFE_CMD_LIST 
 * Below are the param table for each CMD, refer to detailed manual
 *                             | ENGINE *e, |   int cmd,                   |    long i,      |     void *p,               |  void(*f)(void)  |
  STSAFE_CMD_GET_PRODUCT_DATA  |      e     | STSAFE_CMD_GET_PRODUCT_DATA  |      0          | NULL for now, print info   |     NULL         |     
  STSAFE_CMD_GET_DEVICE_CERT   |      e     | STSAFE_CMD_GET_DEVICE_CERT   |      0          | File name to dump the cert |     NULL         |     
  STSAFE_CMD_SET_SIG_KEY_SLOT  |      e     | STSAFE_CMD_SET_SIG_KEY_SLOT  | slot number     |      NULL                  |     NULL         |     
  STSAFE_CMD_SET_GEN_KEY_SLOT  |      e     | STSAFE_CMD_SET_GEN_KEY_SLOT  | slot number     |      NULL                  |     NULL         |     
  STSAFE_CMD_SET_MEMORY_REGION |      e     | STSAFE_CMD_SET_MEMORY_REGION | region number   |      NULL                  |     NULL         |     
  STSAFE_CMD_WRITE_DEVICE_CERT |      e     | STSAFE_CMD_WRITE_DEVICE_CERT |      0          | File name to read from     |     NULL         |     
  STSAFE_CMD_RESET             |      e     | STSAFE_CMD_RESET             |      0          |      NULL                  |     NULL         |     
  STSAFE_CMD_ECHO              |      e     | STSAFE_CMD_ECHO              |      0          | Input string to echo       |     NULL         |
  STSAFE_CMD_HIBERNATE         |      e     | STSAFE_CMD_HIBERNATE         | Wakeup code     |      NULL                  |     NULL         |     
  STSAFE_CMD_VERIFYPASSWORD    |      e     | STSAFE_CMD_VERIFYPASSWORD    |      0          | Input/Output byte string   |     NULL         |     
  STSAFE_CMD_QUERY             |      e     | STSAFE_CMD_QUERY             |      0          | Item to query as string    |     NULL         |
 * 
 * */
int stsafe_cmd_ctrl(ENGINE *e, int cmd, long i, void *p, void(*f)(void));

/* Set of PKEY API functions */
EVP_PKEY* stsafe_load_pubkey(ENGINE *, const char *, UI_METHOD *, void *);
EVP_PKEY* stsafe_load_privkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data);
int stsafe_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pkey_meth, const int **nids, int nid);
int stsafe_pkey_meth_init(void);

/* Wrap/Unwrap */
/**
  * name:   stsafe_AES_wrap_key
  *          This command performs local envelope wrap
  *
  * param   keyslot  : Local envelope key slot number.\n
  *                    Can be one of the following values:\n
  *                    @arg STSAFEA_KEY_SLOT_0: Slot 0 in local envelope key table.\n
  *                    @arg STSAFEA_KEY_SLOT_1: Slot 1 in local envelope key table.
  * param   out      : Pointer to the output wrapped data bytes, must be pre-allocated, 
  *                    size should be at least in + 8
  * param   in    : Pointer to data bytes array to wrap.
  * param   inlen : Data size (multiple of 8 bytes between 16 and 488 bytes inclusive).
  * retval  0 if success, 1 otherwise.
  */
int stsafe_AES_wrap_key(unsigned char keyslot, unsigned char *out, const unsigned char *in, unsigned int inlen);

/**
  * name:   stsafe_AES_unwrap_key
  *          This command performs local envelope unwrap
  *
  * param   keyslot  : Local envelope key slot number.\n
  *                    Can be one of the following values:\n
  *                    @arg STSAFEA_KEY_SLOT_0: Slot 0 in local envelope key table.\n
  *                    @arg STSAFEA_KEY_SLOT_1: Slot 1 in local envelope key table.
  * param   out      : Pointer to the output wrapped data bytes, must be pre-allocated, 
  *                    size should be at least size of in 
  * param   in    : Pointer to data bytes array to wrap.
  * param   inlen : Data size (multiple of 8 bytes between 16 and 488 bytes inclusive).
  * retval  0 if success, 1 otherwise.
  */
int stsafe_AES_unwrap_key(unsigned char keyslot, unsigned char *out, const unsigned char *in, unsigned int inlen);

/* ECDSA functions */
EC_KEY_METHOD *stsafe_get_EC_methods(void);

ECDSA_SIG *stsafe_engine_ecdsa_do_sign (const unsigned char *dgst, int dgst_len,
                                        const BIGNUM *kinv, const BIGNUM *rp,
                                        EC_KEY *in_eckey);

int stsafe_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                   unsigned char *sig, unsigned int *siglen,
                   const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

int stsafe_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                     const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

int stsafe_engine_ecdh_compute_key(unsigned char **out,
                                size_t *outlen,
                                const EC_POINT *pub_key,
                                const EC_KEY *ecdh);
                                
int stsafe_ec_generate_key(EC_KEY *eckey);

/* RAND */
int stsafe_get_random_bytes(unsigned char *buffer, int num);


/* Data Partition (Zone) Read/Update/Decrement */
/**
  * name:   stsafe_read_zone
  *         This function read data from a data partition zone
  *
  * param   zone_index  : Specify the Zone Index .\n
  * param   offset      : Starting offset to read the data from
  *                       Range supported is from 0 up to the length of the data segment.
  * param   length      : Number of bytes to read, Must be strictly larger than 0.
  * param   data_buffer : Output Data buffer. Must be allocated by the caller.
  * retval  0 if success, 1 otherwise.
  */
int stsafe_read_zone(int zone_index, int offset, int length, unsigned char *data_buff);

/**
  * name:   stsafe_update_zone
  *         This function write data to a data partition zone
  *
  * param   zone_index  : Specify the Zone Index .\n
  * param   offset      : Starting offset to write the data to
  *                       Range supported is from 0 up to the length of the data segment.
  * param   length      : Number of bytes to write, Must be strictly larger than 0.
  * param   data_buffer : Input Data buffer. Must be allocated by the caller.
  * retval  0 if success, 1 otherwise.
  */
int stsafe_update_zone(int zone_index, int offset, int length, unsigned char *data_buff);

/**
  * name:   stsafe_zone_decrement
  *         This function update a data partition zone and decrement the one-way counter
  *
  * param   zone_index    : Specify the Zone Index .\n
  * param   offset        : Starting offset to decrement the counter
  * param   amount        : Amount to be decreased to the one-way counter.
  * param   Indata_buffer : Input Data buffer. Must be allocated by the caller.
  * param   Indata_length : Input Data length.
  * param   outcounter    : Pointer to Output decrement counter. Must be allocated by the caller.
  * retval  0 if success, 1 otherwise.
  */
int stsafe_zone_decrement(int zone_index, int offset, int amount, unsigned char *indata_buffer, int indata_length, unsigned char *outcounter);


#endif /* STSAFE_INIT_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
