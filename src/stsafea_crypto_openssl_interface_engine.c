/**
  ******************************************************************************
  * @file    stsafea_crypto_stdlib_interface_template.c
  * @author  SMD/AME application teams
  * @version V3.3.0
  * @brief   Crypto Interface file to support the crypto services required by the
  *          STSAFE-A Middleware and offered by the STM32 crypto library:
  *           + Key Management
  *           + SHA
  *           + AES
  ******************************************************************************
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
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/cmac.h"
#include "openssl/sha.h"
#include "stsafea_crypto.h"
#include "stsafea_interface_conf.h"
#include "openssl/err.h"


#include "stsafe_init.h"
#include "stsafe_api.h"
#include "stsafea_types.h"
#include "stsafea_core.h"
#include "stsafea_conf.h"
#include "stsafea_service.h"


/* Private typedef -----------------------------------------------------------*/

/* Private defines -----------------------------------------------------------*/

/* Private macros ------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/
static uint8_t  aHostCipherKey[] = {0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88}; /*!< STSAFE-A's Host cipher key */
static uint8_t  aHostMacKey   [] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}; /*!< STSAFE-A's Host Mac key */


/* Global variables ----------------------------------------------------------*/

/* Private function prototypes -----------------------------------------------*/

/* Functions Definition ------------------------------------------------------*/

/** @addtogroup CRYPTO_IF_Exported_Functions_Group1 Host MAC and Cipher keys Initialization
  *  @brief    Crypto Interface APIs to be implemented at application level. Templates are provided.
  *
@verbatim
 ===============================================================================
           ##### Host MAC and Cipher keys Initialization functions #####
 ===============================================================================

@endverbatim
  * @{
  */

/**
  * @brief   StSafeA_HostKeys_Init
  *          Initialize STSAFE-Axxx Host MAC and Cipher Keys that will be used by the crypto interface layer
  * @note    For now the keys are pre-loaded and known. The keys are provided above : aHostCipherKey and aHostMacKey
  *          The customer should provide a method to pre-load and update the key information here. 
  *
  * @param   None
  * @retval  0 if success. An error code otherwise
  */
int32_t StSafeA_HostKeys_Init()
{
#if (USE_PRE_LOADED_HOST_KEYS)

#if 0 /* not the case for non-ST platform, so we just commented out them below. */

  /* This is just a very easy example to retrieve keys pre-loaded at the end of the MCU Flash
     and load them into the SRAM. Host MAC and Chiper Keys are previously pre-stored at the end 
     of the MCU flash (e.g. by the SDK Pairing Application example) .
     It's up to the user to protect the MAC and Chiper keys and to find the proper
     and most secure way to retrieve them when needed or to securely keep them into
     a protected volatime memory during the application life */

  /* Host MAC Key */
  uint32_t host_mac_key_addr = FLASH_BASE + FLASH_SIZE - 2U * (STSAFEA_HOST_KEY_LENGTH);

  /* Host Cipher Key */
  uint32_t host_cipher_key_addr = FLASH_BASE + FLASH_SIZE - (STSAFEA_HOST_KEY_LENGTH);

  /* Set and keep the keys that will be used during the Crypto / MAC operations */
  (void)memcpy(aHostMacKey, (uint8_t *)host_mac_key_addr,    STSAFEA_HOST_KEY_LENGTH);
  (void)memcpy(aHostCipherKey, (uint8_t *)host_cipher_key_addr, STSAFEA_HOST_KEY_LENGTH);
#endif
  
#else
  /* Nothing implemented here. Customer may provide a way to update the aHostCipherKey and aHostMacKey here. */
#endif /* USE_PRE_LOADED_HOST_KEYS */

  return 0;
}


/**
  * @brief   StSafeA_HostKeys_Program
  *          Program STSAFE-Axxx Host MAC and Cipher Keys that will be used by the crypto interface layer
  * @note    In case the Keys are pre-loaded it does nothing.
  *          In case it is not pre-loaded, this function will attempt to program the keys stored in the 
  *          aHostCipherKey and aHostMacKey to the hardware.
  *
  * @param   None
  * @retval  0 if success. An error code otherwise
  */
int32_t StSafeA_HostKeys_Program(void)
{
  int32_t StatusCode = 0;
  

#if !(USE_PRE_LOADED_HOST_KEYS)

  StSafeA_Handle_t *pStSafeA = &stsafea_handle;
  uint8_t keys[32];
  memcpy(&keys[0], aHostMacKey, STSAFEA_HOST_KEY_LENGTH);
  memcpy(&keys[STSAFEA_HOST_KEY_LENGTH], aHostCipherKey, STSAFEA_HOST_KEY_LENGTH);
  printf("Programming the host and cipher keys.\n");
  StatusCode = StSafeA_PutAttribute(pStSafeA, STSAFEA_TAG_HOST_KEY_SLOT, keys,
                                    sizeof(keys)/sizeof(keys[0]),
                                    STSAFEA_MAC_NONE);
#endif

  return StatusCode;
}


/**
  * @}
  */


#if (USE_SIGNATURE_SESSION)

/** @addtogroup CRYPTO_IF_Exported_Functions_Group2 HASH Functions
  *  @brief    Crypto Interface APIs to be implemented at application level. Templates are provided.
  *
@verbatim
 ===============================================================================
                          ##### HASH functions #####
 ===============================================================================

@endverbatim
  * @{
  */

/**
  * @brief   StSafeA_SHA_Free
  *          SHA final function to free allocated buffer for the SHA Digest
  *
  * @param   in_hash_type : type of SHA
  *          This parameter can be one of the StSafeA_HashTypes_t enum values:
  *            @arg STSAFEA_SHA_256: 256-bits
  *            @arg STSAFEA_SHA_384: 384-bits
  * @param   in_sha_ctx : SHA context to be finalized
  * @retval  None
  */
void StSafeA_SHA_Free(StSafeA_HashTypes_t in_hash_type, void** in_sha_ctx)
{
    switch (in_hash_type)
    {
    case STSAFEA_SHA_256:
        if (*in_sha_ctx != NULL)
        {
            EVP_MD_CTX_free(*in_sha_ctx);
        }

        *in_sha_ctx = NULL;
        break;

    case STSAFEA_SHA_384:
        if (*in_sha_ctx != NULL)
        {
            EVP_MD_CTX_free(*in_sha_ctx);
        }

        *in_sha_ctx = NULL;
        break;

    default:
        break;
    }
}

/**
  * @brief   StSafeA_SHA_Init
  *          SHA initialization function to initialize the SHA context
  *
  * @param   in_hash_type : type of SHA
  *          This parameter can be one of the StSafeA_HashTypes_t enum values:
  *            @arg STSAFEA_SHA_256: 256-bits
  *            @arg STSAFEA_SHA_384: 384-bits
  * @param   in_sha_ctx : SHA context to be initialized
  * @retval  None
  */
void StSafeA_SHA_Init(StSafeA_HashTypes_t in_hash_type, void** in_sha_ctx)
{
    switch (in_hash_type)
    {
    case STSAFEA_SHA_256:
        if (*in_sha_ctx != NULL)
        {
            StSafeA_SHA_Free(in_hash_type, &*in_sha_ctx);
        }
        *in_sha_ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(*in_sha_ctx, EVP_sha256(), NULL);
        break;

    case STSAFEA_SHA_384:
        if (*in_sha_ctx != NULL)
        {
            StSafeA_SHA_Free(in_hash_type, &*in_sha_ctx);
        }
        *in_sha_ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(*in_sha_ctx, EVP_sha384(), NULL);
        break;

    default:
        break;
    }
}


/**
  * @brief   StSafeA_SHA_Update
  *          SHA update function to process SHA over a message data buffer.
  *
  * @param   in_hash_type : type of SHA
  *          This parameter can be one of the StSafeA_HashTypes_t enum values:
  *            @arg STSAFEA_SHA_256: 256-bits
  *            @arg STSAFEA_SHA_384: 384-bits
  * @param   in_sha_ctx : SHA context
  * @param   in_input_message : message data buffer
  * @param   in_input_message_length : message data buffer length
  * @retval  None
  */
  
void StSafeA_SHA_Update(StSafeA_HashTypes_t in_hash_type, void* in_sha_ctx,
                        uint8_t* in_input_message, uint32_t in_input_message_length)
{
    switch (in_hash_type)
    {
    case STSAFEA_SHA_256:
        if (in_sha_ctx != NULL)
        {
            EVP_DigestUpdate(in_sha_ctx, in_input_message, in_input_message_length);
        }
        break;

    case STSAFEA_SHA_384:
        if (in_sha_ctx != NULL)
        {
            EVP_DigestUpdate(in_sha_ctx, in_input_message, in_input_message_length);
        }
        break;

    default:
        break;
    }
}


/**
  * @brief   StSafeA_SHA_Final
  *          SHA final function to finalize the SHA Digest
  *
  * @param   in_hash_type : type of SHA
  *          This parameter can be one of the StSafeA_HashTypes_t enum values:
  *            @arg STSAFEA_SHA_256: 256-bits
  *            @arg STSAFEA_SHA_384: 384-bits
  * @param   in_sha_ctx : SHA context to be finalized
  * @param   in_message_digest : message digest data buffer
  * @retval  None
  */

void StSafeA_SHA_Final(StSafeA_HashTypes_t in_hash_type, void** in_sha_ctx, uint8_t* in_message_digest)
{
    uint32_t digest_length;

    switch (in_hash_type)
    {
    case STSAFEA_SHA_256:
        if (*in_sha_ctx != NULL)
        {
            EVP_DigestFinal_ex(*in_sha_ctx, in_message_digest, &digest_length);
        }
        break;

    case STSAFEA_SHA_384:
        if (*in_sha_ctx != NULL)
        {
            EVP_DigestFinal_ex(*in_sha_ctx, in_message_digest, &digest_length);
        }
        break;

    default:
        break;
    }
}


#endif /* USE_SIGNATURE_SESSION */

/**
  * @}
  */
  
/**
  * @brief   handleErrors
  *          Error reporting function, it looks up the openssl error and reports it.
  *
  * @param   none
  * @retval  None
  */
static void
handleErrors(void)
{
    char          opensslerrbuff[1024];
    unsigned long opensslerr    = 0;

    opensslerr = ERR_get_error();
    if (ERR_error_string(opensslerr, opensslerrbuff) != 0) {
        fprintf(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
    }
}

/** @addtogroup CRYPTO_IF_Exported_Functions_Group3 AES Functions
  *  @brief    Crypto Interface APIs to be implemented at application level. Templates are provided.
  *
@verbatim
 ===============================================================================
                          ##### AES functions #####
 ===============================================================================

@endverbatim
  * @{
  */

/**
  * @brief   StSafeA_AES_MAC_Start
  *          Start AES MAC computation
  *
  * @param   in_aes_mac_ctx : AES MAC context
  * @retval  None
  */
void StSafeA_AES_MAC_Start(void** in_aes_mac_ctx)
{
    if (*in_aes_mac_ctx != NULL)
    {
        CMAC_CTX_cleanup(*in_aes_mac_ctx);
        CMAC_CTX_free(*in_aes_mac_ctx);
        *in_aes_mac_ctx = NULL;
    }

    *in_aes_mac_ctx = CMAC_CTX_new();

    if (*in_aes_mac_ctx != NULL)
    {
        CMAC_Init(*in_aes_mac_ctx, aHostMacKey, 16, EVP_aes_128_cbc(), NULL);
    }
}

/**
  * @brief   StSafeA_AES_MAC_Update
  *          Update / Add data to MAC computation
  *
  * @param   in_data : data buffer
  * @param   in_length : data buffer length
  * @param   in_aes_mac_ctx : AES MAC context
  * @retval  None
  */
void StSafeA_AES_MAC_Update(uint8_t* in_data, uint16_t in_length, void* in_aes_mac_ctx)
{
    if (in_aes_mac_ctx != NULL)
    {
        CMAC_Update(in_aes_mac_ctx, in_data, in_length);
    }
}

/**
  * @brief   StSafeA_AES_MAC_LastUpdate
  *          Update / Add data to MAC computation
  *
  * @param   in_data : data buffer
  * @param   in_length : data buffer length
  * @param   in_aes_mac_ctx : AES MAC context
  * @retval  None
  */
void StSafeA_AES_MAC_LastUpdate(uint8_t* in_data, uint16_t in_length, void* in_aes_mac_ctx)
{
    if (in_aes_mac_ctx != NULL)
    {
        CMAC_Update(in_aes_mac_ctx, in_data, in_length);
    }
}
  

/**
  * @brief   StSafeA_AES_MAC_Final
  *          Finalize AES MAC computation
  *
  * @param   out_mac : calculated MAC
  * @param   in_aes_mac_ctx : AES MAC context
  * @retval  None
  */
void StSafeA_AES_MAC_Final(uint8_t* out_mac, void** in_aes_mac_ctx)
{
    size_t size;
    uint8_t l_mac[16] = {0, };

    if (*in_aes_mac_ctx != NULL)
    {
        CMAC_Final(*in_aes_mac_ctx, &l_mac[0], &size);
        CMAC_CTX_cleanup(*in_aes_mac_ctx);
        CMAC_CTX_free(*in_aes_mac_ctx);
        *in_aes_mac_ctx = NULL;
    }
    memcpy(out_mac, &l_mac[0], STSAFEA_MAC_LENGTH);
}  

/**
  * @brief   StSafeA_AES_ECB_Encrypt
  *          AES ECB Encryption
  *
  * @param   in_data : plain data buffer
  * @param   out_data : encrypted output data buffer
  * @param   in_aes_type : type of AES. Can be one of the following values:
  *            @arg STSAFEA_KEY_TYPE_AES_128: AES 128-bits
  *            @arg STSAFEA_KEY_TYPE_AES_256: AES 256-bits
  * @retval  0 if success, an error code otherwise
  */
int32_t StSafeA_AES_ECB_Encrypt(uint8_t* in_data, uint8_t* out_data,
                                uint8_t in_aes_type)
{
    int32_t status_code = 0;
    EVP_CIPHER_CTX* ctx;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handleErrors();
        goto end;
    }

    if (! EVP_CIPHER_CTX_set_padding(ctx, EVP_CIPH_NO_PADDING)) {
        handleErrors();
        goto end;
    }

    switch (in_aes_type)
    {
    case STSAFEA_KEY_TYPE_AES_128:
    {
        int32_t size = 16;

        if (! EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aHostCipherKey, NULL)) {
            handleErrors();
            goto end;
        }
        status_code = EVP_EncryptUpdate(ctx, out_data, &size, in_data, size);
    }
        break;

    case STSAFEA_KEY_TYPE_AES_256:
    {
        int32_t size = 32;

        if (! EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aHostCipherKey, NULL)) {
            handleErrors();
            goto end;
        }
        status_code = EVP_EncryptUpdate(ctx, out_data, &size, in_data, size);
    }
        break;

    default:
        status_code = 1;
        break;
    }

end:
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    if (status_code == 1)
    {
        return 0;
    }

    if (status_code == 0)
    {
        return 1;
    }

    return status_code;
}

/**
  * @brief   StSafeA_AES_CBC_Encrypt
  *          AES CBC Encryption
  *
  * @param   in_data : plain data buffer
  * @param   in_length : plain data buffer length
  * @param   out_data : encrypted output data buffer
  * @param   in_initial_value : initial value
  * @param   in_aes_type : type of AES. Can be one of the following values:
  *            @arg STSAFEA_KEY_TYPE_AES_128: AES 128-bits
  *            @arg STSAFEA_KEY_TYPE_AES_256: AES 256-bits
  * @retval  0 if success, an error code otherwise
  */
int32_t StSafeA_AES_CBC_Encrypt(uint8_t* in_data, uint16_t in_length, uint8_t* out_data,
                                uint8_t* in_initial_value, uint8_t in_aes_type)
{
    int32_t status_code = 0;
    EVP_CIPHER_CTX* ctx;
    int size;


    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handleErrors();
        goto end;
    }

    if (! EVP_CIPHER_CTX_set_padding(ctx, EVP_CIPH_NO_PADDING)) {
        handleErrors();
        goto end;
    }

    switch (in_aes_type)
    {
    case STSAFEA_KEY_TYPE_AES_128:
        if (! EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aHostCipherKey, in_initial_value)) {
            handleErrors();
            goto end;
        }
        status_code = EVP_EncryptUpdate(ctx, out_data, &size, in_data, in_length);
        break;

    case STSAFEA_KEY_TYPE_AES_256:
        if (! EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aHostCipherKey, in_initial_value)) {
            handleErrors();
            goto end;
        }
        status_code = EVP_EncryptUpdate(ctx, out_data, &size, in_data, in_length);
        break;

    default:
        status_code = 1;
        break;
    }

end:
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    if (status_code == 1)
    {
        return 0;
    }

    if (status_code == 0)
    {
        return 1;
    }

    return status_code;
}


/**
  * @brief   StSafeA_AES_CBC_Decrypt
  *          AES CBC Decryption
  *
  * @param   in_data : encrypted data buffer
  * @param   in_length : encrypted data buffer length
  * @param   out_data : plain output data buffer
  * @param   in_initial_value : initial value
  * @param   in_aes_type : type of AES. Can be one of the following values:
  *            @arg STSAFEA_KEY_TYPE_AES_128: AES 128-bits
  *            @arg STSAFEA_KEY_TYPE_AES_256: AES 256-bits
  * @retval  0 if success, an error code otherwise
  */
int32_t StSafeA_AES_CBC_Decrypt(uint8_t* in_data, uint16_t in_length, uint8_t* out_data, 
                                uint8_t* in_initial_value, uint8_t in_aes_type)
{
    int32_t status_code = 0;
    EVP_CIPHER_CTX* ctx;
    int size;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handleErrors();
        goto end;
    }

    if (! EVP_CIPHER_CTX_set_padding(ctx, EVP_CIPH_NO_PADDING)) {
        handleErrors();
        goto end;
    }

    switch (in_aes_type)
    {
    case STSAFEA_KEY_TYPE_AES_128:
        if (! EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aHostCipherKey, in_initial_value)) {
            handleErrors();
            goto end;
        }
        //status_code = EVP_EncryptUpdate(ctx, out_data, &size, in_data, in_length);
        status_code = EVP_DecryptUpdate(ctx, out_data, &size, in_data, in_length);
        break;

    case STSAFEA_KEY_TYPE_AES_256:
        if (! EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aHostCipherKey, in_initial_value)) {
            handleErrors();
            goto end;
        }
        status_code = EVP_DecryptUpdate(ctx, out_data, &size, in_data, in_length);
        break;

    default:
        status_code = 1;
        break;
    }

end:
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    if (status_code == 1)
    {
        return 0;
    }

    if (status_code == 0)
    {
        return 1;
    }

    return status_code;
}

/**
  * @}
  */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
