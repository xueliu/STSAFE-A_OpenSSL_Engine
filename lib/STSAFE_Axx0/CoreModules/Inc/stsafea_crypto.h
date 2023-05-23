/**
  ******************************************************************************
  * @file    stsafea_crypto.h
  * @author  SMD application team
  * @version V3.3.6
  * @brief   Header file of STSAFE-A Middleware Crypto module.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2016 STMicroelectronics</center></h2>
  *
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */


/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef STSAFEA_CRYPTO_H
#define STSAFEA_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Includes ------------------------------------------------------------------*/
#include "stsafeaxxx.h"

/** @addtogroup STSAFE_A1XX_CORE_MODULES
  * @{
  */


/** @addtogroup CRYPTO
  * @{
  */


/* Exported types ------------------------------------------------------------*/

/* Exported constants --------------------------------------------------------*/

/* External variables --------------------------------------------------------*/

/* Exported macros -----------------------------------------------------------*/

/* Exported functions ------------------------------------------------------- */
/** @addtogroup CRYPTO_Exported_Functions
  * @{
  */
void StSafeA_InitHASH(StSafeA_Handle_t *pStSafeA);
void StSafeA_ComputeHASH(StSafeA_Handle_t *pStSafeA);
void StSafeA_ComputeCMAC(StSafeA_Handle_t *pStSafeA);
void StSafeA_ComputeRMAC(StSafeA_Handle_t *pStSafeA);
StSafeA_ResponseCode_t StSafeA_DataEncryption(StSafeA_Handle_t *pStSafeA);
StSafeA_ResponseCode_t StSafeA_DataDecryption(StSafeA_Handle_t *pStSafeA);
StSafeA_ResponseCode_t StSafeA_MAC_SHA_PrePostProcess(StSafeA_Handle_t *pStSafeA,
                                                      StSafeA_MacShaProcess_t MacShaProcessType);
/**
  * @}
  */


/* Interface weak functions ***************************************************/
/** @addtogroup CRYPTO_Interface_Functions
  * @{
  */
int32_t StSafeA_HostKeys_Init(void);
void    StSafeA_SHA_Init(StSafeA_HashTypes_t InHashType, void **ppShaCtx);
void    StSafeA_SHA_Update(StSafeA_HashTypes_t InHashType, void *pShaCtx, uint8_t *pInMessage,
                           uint32_t InMessageLength);
void    StSafeA_SHA_Final(StSafeA_HashTypes_t InHashType, void **ppShaCtx, uint8_t *pMessageDigest);
void    StSafeA_AES_MAC_Start(void **ppAesMacCtx);
void    StSafeA_AES_MAC_Update(uint8_t *pInData, uint16_t InDataLength, void *pAesMacCtx);
void    StSafeA_AES_MAC_LastUpdate(uint8_t *pInData, uint16_t InDataLength, void *pAesMacCtx);
void    StSafeA_AES_MAC_Final(uint8_t *pOutMac, void **ppAesMacCtx);
int32_t StSafeA_AES_ECB_Encrypt(uint8_t *pInData, uint8_t *pOutData, uint8_t InAesType);
int32_t StSafeA_AES_CBC_Encrypt(uint8_t *pInData, uint16_t InDataLength, uint8_t *pOutData, uint8_t *InInitialValue,
                                uint8_t InAesType);
int32_t StSafeA_AES_CBC_Decrypt(uint8_t *pInData, uint16_t InDataLength, uint8_t *pOutData, uint8_t *InInitialValue,
                                uint8_t InAesType);
/**
  * @}
  */


/**
  * @}
  */


/**
  * @}
  */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* STSAFEA_CRYPTO_H */



