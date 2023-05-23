/**
  ******************************************************************************
  * @file    stsafea_service.h
  * @author  SMD application team
  * @version V3.3.6
  * @brief   Header file of STSAFE-A Middleware Service module.
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
#ifndef STSAFEA_SERVICE_H
#define STSAFEA_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Includes ------------------------------------------------------------------*/
#include "stsafeaxxx.h"

/** @addtogroup STSAFE_A1XX_CORE_MODULES
  * @{
  */


/** @addtogroup SERVICE
  * @{
  */


/* Exported types ------------------------------------------------------------*/
/** @addtogroup SERVICE_Exported_Types
  * @{
  */
typedef struct
{
  int32_t (* IOInit)(void);
  int32_t (* BusInit)(void);
  int32_t (* BusDeInit)(void);
  int32_t (* BusRecv)(uint16_t address, uint8_t *, uint16_t);
  int32_t (* BusSend)(uint16_t address, uint8_t *, uint16_t);
  void (* TimeDelay)(uint32_t msDelay);
  int32_t (*CrcInit)(void);
  uint32_t (*CrcCompute)(uint8_t *pData1, uint16_t Length1, uint8_t *pData2, uint16_t Length2);
  uint16_t DevAddr;
} STSAFEA_HW_t;
/**
  * @}
  */

/* Exported constants --------------------------------------------------------*/
/** @addtogroup SERVICE_Error_Constants Generic Low Level error definitions to maintain platform independency
  * @{
  */
#define STSAFEA_BUS_OK   ( 0)
#define STSAFEA_BUS_ERR  (-1)
#define STSAFEA_BUS_NACK ( 1)

/**
  * @}
  */

/* External variables --------------------------------------------------------*/

/* Exported macros -----------------------------------------------------------*/

/* Exported functions ------------------------------------------------------- */
/** @addtogroup SERVICE_Exported_Functions
  * @{
  */

/** @addtogroup SERVICE_Exported_Functions_Group1 Initialization / Configuration APIs
  *  @brief    STSAFE-A Service APIs related to initialization and configuration
  *
@verbatim
 ===============================================================================
              ##### Initialization/Configuration functions #####
 ===============================================================================

@endverbatim
  * @{
  */
int8_t StSafeA_HW_Init(void);
/**
  * @}
  */


/** @addtogroup SERVICE_Exported_Functions_Group2 Low Level operation APIs
  *  @brief    STSAFE-A Service APIs related to low level operations
  *
@verbatim
 ===============================================================================
              ##### Low Level operation functions #####
 ===============================================================================

@endverbatim
  * @{
  */

StSafeA_ResponseCode_t StSafeA_Transmit(StSafeA_TLVBuffer_t *pTLV_Buffer, uint8_t CrcSupport);
StSafeA_ResponseCode_t StSafeA_Receive(StSafeA_TLVBuffer_t *pTLV_Buffer, uint8_t CrcSupport);
void                   StSafeA_Delay(uint32_t msDelay);
/**
  * @}
  */


/**
  * @}
  */


/* Interface weak functions ***************************************************/
/** @addtogroup SERVICE_Interface_Functions
  *  @brief    These functions MUST be implemented at application layer
  * @{
  */
int8_t StSafeA_HW_Probe(void  *pCtx);
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

#endif /* STSAFEA_SERVICE_H */

