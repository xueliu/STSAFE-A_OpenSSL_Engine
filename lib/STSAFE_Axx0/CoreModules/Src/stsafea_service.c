/**
  ******************************************************************************
  * @file    stsafea_service.c
  * @author  SMD application team
  * @version V3.3.6
  * @brief   STSAFE-A Middleware Service module.
  *          Provide Low Level services such as communication bus, IOs etc such as:
  *           + Initialization and Configuration functions
  *           + Low Level operation functions
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

/* Includes ------------------------------------------------------------------*/
#include "stsafea_service.h"
#include <string.h>

/** MISRA C:2012 deviation rule has been granted for following rules:
  * - Rule-14.3_a - Medium: Conditional expression is always true.
  * - Rule-14.3_b - Medium: Conditional expression is always false.
  */


/** @addtogroup STSAFE_A1XX_CORE_MODULES
  * @{
  */

/** @addtogroup SERVICE
  * @{
  */

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/** @addtogroup SERVICE_Private_Constants
  * @{
  */

/* Max I2C polling delay in ms */
#ifndef STSAFEA_I2C_POLLING_MAX
#define STSAFEA_I2C_POLLING_MAX              2500U
#endif

/* I2C polling step in ms */
#ifndef STSAFEA_I2C_POLLING_STEP
#define STSAFEA_I2C_POLLING_STEP                3U
#endif
/**
  * @}
  */


/* Private macro -------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/
/** @addtogroup SERVICE_Private_Variables
  * @{
  */
static STSAFEA_HW_t HwCtx;
/**
  * @}
  */


/* Global variables ----------------------------------------------------------*/

/* Private function prototypes -----------------------------------------------*/
static int8_t   StSafeA_SendBytes(StSafeA_TLVBuffer_t *pInBuffer);
static int8_t   StSafeA_ReceiveBytes(StSafeA_TLVBuffer_t *pOutBuffer);
static void     StSafeA_Crc16(StSafeA_TLVBuffer_t *pTLV_Buffer);

/* Functions Definition ------------------------------------------------------*/
/** @addtogroup SERVICE_Exported_Functions
  * @{
  */

/** @addtogroup SERVICE_Exported_Functions_Group1 Initialization / Configuration APIs
  *  @brief    STSAFE-A Service APIs related to to initialization and configuration
  *
@verbatim
 ===============================================================================
              ##### Initialization/Configuration functions #####
 ===============================================================================

@endverbatim
  * @{
  */

/**
  * @brief  StSafeA_HW_Init
  *         Initialize the communication bus and the IO pins needed to operate the STSAFE-A1xx device
  * @note   No other Service APIs can be called/used if this one has never been successfully called first.
  *         The StSafeA_HW_Probe function must have been implemented at service interface layer.
  *
  * @param  None
  * @retval 0 if success, an error code otherwise.
  */
int8_t StSafeA_HW_Init(void)
{
  int8_t ret = StSafeA_HW_Probe(&HwCtx);

  if ((HwCtx.IOInit == NULL) ||
      (HwCtx.BusInit == NULL) ||
      (HwCtx.BusSend == NULL) ||
      (HwCtx.BusRecv == NULL) ||
      (HwCtx.CrcInit == NULL) ||
      (HwCtx.CrcCompute == NULL) ||
      (HwCtx.TimeDelay == NULL))
  {
    return STSAFEA_BUS_ERR;
  }

  if (STSAFEA_BUS_OK == ret)
  {
    /* Initialize the STSAFE-A  IO */
    ret = HwCtx.IOInit();
  }

  if (STSAFEA_BUS_OK == ret)
  {
    /* Initialize the STSAFE-A communication Bus */
    ret = HwCtx.BusInit();
  }

  if (STSAFEA_BUS_OK == ret)
  {
    /* Initialize the STSAFE-A CRC */
    ret = HwCtx.CrcInit();
  }

  return ret;
}

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

/**
  * @brief   StSafeA_Transmit
  *          Prepare the command to be transmitted and call the low level bus to execute.
  *          Compute and concatenate CRC if supported.
  *
  * @param   pTLV_Buffer : Tag-Length-Value structure pointer to be transmitted over the bus.
  * @param   CrcSupport  : 0 if CRC is not supported, any other values otherwise.
  * @retval  STSAFEA_OK if success,  an error code otherwise.
  */
StSafeA_ResponseCode_t StSafeA_Transmit(StSafeA_TLVBuffer_t *pTLV_Buffer,  uint8_t CrcSupport)
{
  StSafeA_ResponseCode_t status_code = STSAFEA_INVALID_PARAMETER;
  if (pTLV_Buffer != NULL)
  {
    /* Compute & concatenate CRC to buffer */
    if (CrcSupport != 0U)
    {
      StSafeA_Crc16(pTLV_Buffer);
    }

    status_code = (StSafeA_ResponseCode_t)StSafeA_SendBytes(pTLV_Buffer);

    if (status_code != STSAFEA_BUFFER_LENGTH_EXCEEDED)
    {
      if (status_code == (StSafeA_ResponseCode_t)STSAFEA_BUS_OK)
      {
        status_code = STSAFEA_OK;
      }
      else if (status_code == (StSafeA_ResponseCode_t)STSAFEA_BUS_NACK)
      {
        status_code = STSAFEA_COMMUNICATION_NACK;
      }
      else
      {
        status_code = STSAFEA_COMMUNICATION_ERROR;
      }
    }
  }

  return status_code;
}

/**
  * @brief   StSafeA_Receive
  *          Receive data from STSAFE-A1xx  using the low level bus functions to retrieve it.
  *          Check the CRC, if supported.
  *
  * @param   pTLV_Buffer : Tag-Length-Value structure pointer to be filled  with received data
  * @param   CrcSupport  : 0 if CRC is not supported, any other values otherwise.
  * @retval  STSAFEA_OK if success,  an error code otherwise.
  */
StSafeA_ResponseCode_t StSafeA_Receive(StSafeA_TLVBuffer_t *pTLV_Buffer,  uint8_t CrcSupport)
{
  StSafeA_ResponseCode_t status_code = STSAFEA_INVALID_PARAMETER;

  if (pTLV_Buffer != NULL)
  {
    /* Increase buffer size in case of CRC */
    if (CrcSupport != 0U)
    {
      pTLV_Buffer->LV.Length += STSAFEA_CRC_LENGTH;
    }

    status_code = (StSafeA_ResponseCode_t)StSafeA_ReceiveBytes(pTLV_Buffer);

    if (status_code != STSAFEA_BUFFER_LENGTH_EXCEEDED)
    {
      if (status_code == (StSafeA_ResponseCode_t)STSAFEA_BUS_OK)
      {
        status_code = (StSafeA_ResponseCode_t)(uint8_t)((uint8_t)pTLV_Buffer->Header &
                                                        ~(uint8_t)STSAFEA_CMD_HEADER_RMACEN);
      }
      else if (status_code == (StSafeA_ResponseCode_t)STSAFEA_BUS_NACK)
      {
        status_code = STSAFEA_COMMUNICATION_NACK;
      }
      else
      {
        status_code = STSAFEA_COMMUNICATION_ERROR;
      }
    }

    /* Check CRC */
    if ((CrcSupport != 0U) && (status_code == STSAFEA_OK))
    {
      uint16_t crc;
      pTLV_Buffer->LV.Length -= STSAFEA_CRC_LENGTH;
      (void)memcpy(&crc, &pTLV_Buffer->LV.Data[pTLV_Buffer->LV.Length], sizeof(crc));
      StSafeA_Crc16(pTLV_Buffer);

      if (memcmp(&crc, &pTLV_Buffer->LV.Data[pTLV_Buffer->LV.Length - (uint16_t)2],
                 sizeof(crc)) != 0)
      {
        status_code = STSAFEA_INVALID_CRC;
      }
      else
      {
        pTLV_Buffer->LV.Length -= STSAFEA_CRC_LENGTH;
      }
    }
  }

  return status_code;
}

/**
  * @brief   StSafeA_Delay
  *          Provide a delay in milliseconds.
  *
  * @param   msDelay : desired delay in milliseconds.
  * @retval  None
  */
void StSafeA_Delay(uint32_t msDelay)
{
  /* Redirect to the TimeDelay function that has been assigned into the HW Context */
  if (HwCtx.TimeDelay != NULL)
  {
    HwCtx.TimeDelay(msDelay);
  }
}
/**
  * @}
  */

/**
  * @}
  */


/* Interface weak functions definitions --------------------------------------*/

/** @addtogroup SERVICE_Interface_Functions
  *  @brief    These functions MUST be implemented at application layer
  * @{
  */

/**
  * @brief   StSafeA_HW_Probe
  *          Initialize the STSAFE-A1xx low level STSAFEA_HW_t context structure according to the platform (MCU, BSP,
  *          etc).
  * @note    This is a weak function that MUST be implemented at application interface level.
  *          A specific example template stsafea_service_interface_template.c is provided with this Middleware.
  *
  * @param   pCtx : generic void pointer, pointing to the STSAFEA_HW_t context structure to be initialized.
  * @retval  0 if success, an error code otherwise.
  */
__weak int8_t StSafeA_HW_Probe(void  *pCtx)
{
  STSAFEA_UNUSED_PTR(pCtx);
  return STSAFEA_BUS_ERR;
}

/**
  * @}
  */


/* Private functions definitions ---------------------------------------------*/
/** @addtogroup SERVICE_Private_Functions
  * @{
  */

/**
  * @brief   StSafeA_SendBytes
  *          Send data to the STSAFE_A1xx device over the configured Bus .
  *
  * @param   pInBuffer : TLV Structure pointer containing the data to be transmitted
  * @retval  0 if success, an error code otherwise
  */
static int8_t StSafeA_SendBytes(StSafeA_TLVBuffer_t *pInBuffer)
{
  int8_t status_code = STSAFEA_BUS_ERR;
  uint16_t loop = 1;

  uint16_t i2c_length = pInBuffer->LV.Length + STSAFEA_HEADER_LENGTH;

  /* In order to avoid excess data sending over I2C */
  /* pInBuffer->LV.Length should not exceed the max allowed size */
  if (i2c_length > STSAFEA_BUFFER_DATA_PACKET_SIZE)
  {
    return (int8_t)STSAFEA_BUFFER_LENGTH_EXCEEDED;
  }

  if (pInBuffer->LV.Data != NULL)
  {

    /* To optimize stack size and avoid to allocate memory for a dedicated transmit
       buffer, the same pInBuffer.Data is used to send over the Bus. The
       pInBuffer.Data has to be adjusted in the proper way to be used for this scope,
       in order to include the Header as well. LV.Data must be 1-byte greater than expected.
       LV.Data is in fact allocated with 4 additional spare bytes (see STSAFEA_BUFFER_DATA_PACKET_SIZE) */
    (void)memmove((uint8_t *)&pInBuffer->LV.Data[1], (uint8_t *)&pInBuffer->LV.Data[0], pInBuffer->LV.Length);
    pInBuffer->LV.Data[0] = pInBuffer->Header;


    /* Send to STSAFE-A1xx */
    while ((status_code != STSAFEA_BUS_OK) && (loop <= (STSAFEA_I2C_POLLING_MAX / STSAFEA_I2C_POLLING_STEP)))
    {
      status_code = HwCtx.BusSend(((uint16_t)HwCtx.DevAddr) << 1,
                                  (uint8_t *)pInBuffer->LV.Data, i2c_length);

      if (status_code == STSAFEA_BUS_NACK)
      {
        HwCtx.TimeDelay(STSAFEA_I2C_POLLING_STEP);
      }

      loop += STSAFEA_I2C_POLLING_STEP;
    }

    /* Restore initial LV.Data, in case caller expects to re-use it */
    /* At the moment of this implementation Callers functions never need the transmitted LV.Data
       so the following restore can be commented for speed optimization */
    (void)memmove((uint8_t *)&pInBuffer->LV.Data[0], (uint8_t *)&pInBuffer->LV.Data[1], pInBuffer->LV.Length);
  }
  return (status_code);
}

/**
  * @brief   StSafeA_ReceiveBytes
  *          Receive data from the STSAFE_A1xx device over the configured Bus .
  *
  * @param   pOutBuffer : TLV Structure pointer to be filled with the received data
  * @retval  0 if success, an error code otherwise
  */
static int8_t StSafeA_ReceiveBytes(StSafeA_TLVBuffer_t *pOutBuffer)
{
  uint16_t response_length = pOutBuffer->LV.Length;
  int8_t status_code = STSAFEA_BUS_ERR;
  uint16_t loop = 1;

  /* In order to avoid excess data sending over I2C */
  /* pInBuffer->LV.Length should not exceed the max allowed size */
  if ((response_length + STSAFEA_HEADER_LENGTH) > STSAFEA_BUFFER_DATA_PACKET_SIZE)
  {
    return (int8_t)STSAFEA_BUFFER_LENGTH_EXCEEDED;
  }

  if (pOutBuffer->LV.Data != NULL)
  {
    /* To optimize stack size and avoid to allocate memory for a dedicated receive
       buffer, the pOutBuffer.Data is used to receive over the Bus. Than the
       pOutBuffer structure is re-adjusted in the proper way */
    while ((status_code != STSAFEA_BUS_OK) && (loop <= (STSAFEA_I2C_POLLING_MAX / STSAFEA_I2C_POLLING_STEP)))
    {

      status_code = HwCtx.BusRecv(((uint16_t)HwCtx.DevAddr) << 1,
                                  pOutBuffer->LV.Data,
                                  response_length + STSAFEA_HEADER_LENGTH + STSAFEA_LENGTH_SIZE);

      if (status_code == STSAFEA_BUS_NACK)
      {
        HwCtx.TimeDelay(STSAFEA_I2C_POLLING_STEP);
      }

      loop += STSAFEA_I2C_POLLING_STEP;
    }

    /* At this point the pOutBuffer.Header, Length, Data is re-adjusted in the proper way*/
    pOutBuffer->Header = pOutBuffer->LV.Data[0];
    pOutBuffer->LV.Length = ((uint16_t)pOutBuffer->LV.Data[1] << 8) + pOutBuffer->LV.Data[2];
    (void)memcpy(pOutBuffer->LV.Data, &pOutBuffer->LV.Data[3], response_length);

    /* If STSAFE returns a length higher than expected, a new read with the
       updated bytes length is executed */
    if ((pOutBuffer->LV.Length > response_length) && (status_code == 0))
    {
      status_code = STSAFEA_BUS_ERR;
      loop = 1;

      while ((status_code != STSAFEA_BUS_OK) && (loop <= (STSAFEA_I2C_POLLING_MAX / STSAFEA_I2C_POLLING_STEP)))
      {
        status_code = HwCtx.BusRecv(((uint16_t)HwCtx.DevAddr) << 1,
                                    pOutBuffer->LV.Data,
                                    pOutBuffer->LV.Length + STSAFEA_HEADER_LENGTH + STSAFEA_LENGTH_SIZE);

        if (status_code == STSAFEA_BUS_NACK)
        {
          HwCtx.TimeDelay(STSAFEA_I2C_POLLING_STEP);
        }

        loop += STSAFEA_I2C_POLLING_STEP;
      }

      pOutBuffer->Header = pOutBuffer->LV.Data[0];
      pOutBuffer->LV.Length = ((uint16_t)pOutBuffer->LV.Data[1] << 8) + pOutBuffer->LV.Data[2];
      (void)memcpy(pOutBuffer->LV.Data, &pOutBuffer->LV.Data[3], pOutBuffer->LV.Length);

    }
  }
  return (status_code);
}

/**
  * @brief   StSafeA_Crc16
  *          Computes the CRC16 over the Data passed into the TLV structure.
  *
  * @param   pTLV_Buffer : TLV Structure pointer containing the data to calculate the CRC on.
  * @retval  None
  */
void StSafeA_Crc16(StSafeA_TLVBuffer_t *pTLV_Buffer)
{
  if ((pTLV_Buffer != NULL))
  {
    uint16_t crc16;

    crc16 = (uint16_t)HwCtx.CrcCompute(&(pTLV_Buffer->Header),
                                       1U,
                                       pTLV_Buffer->LV.Data,
                                       pTLV_Buffer->LV.Length);

    (void)memcpy(&pTLV_Buffer->LV.Data[pTLV_Buffer->LV.Length], &crc16, sizeof(crc16));
    pTLV_Buffer->LV.Length += STSAFEA_CRC_LENGTH;
  }
}

/**
  * @}
  */


/**
  * @}
  */


/**
  * @}
  */



