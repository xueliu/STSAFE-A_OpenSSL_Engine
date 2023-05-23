/**
  ******************************************************************************
  * @file    stsafea_service_interface.c
  * @author  SMD application team
  * @version V3.3.6
  * @brief   Service Interface file to support the hardware services required by the
  *          STSAFE-A Middleware and offered by the specific HW, Low Level library
  *          selected by the user. E.g.:
  *           + IOs
  *           + Communication Bus (e.g. I2C)
  *           + Timing delay
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
#include "stsafea_interface_conf.h"
#include MCU_PLATFORM_BUS_INCLUDE
#include MCU_PLATFORM_CRC_INCLUDE
#include MCU_PLATFORM_INCLUDE

/* Private typedef -----------------------------------------------------------*/

/* Private define ------------------------------------------------------------*/
#define STSAFEA_DEVICE_ADDRESS                    0x0020

#define I2C_Init                                  BSP_I2C1_Init
#define I2C_DeInit                                BSP_I2C1_DeInit

/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/

/* Private function prototypes -----------------------------------------------*/
int32_t I2C_Send(uint16_t DevAddr, uint8_t *pData, uint16_t Length);
int32_t I2C_Recv(uint16_t DevAddr, uint8_t *pData, uint16_t Length);

/* Private functions ---------------------------------------------------------*/
/**
  * @brief  I2C_Send
  *         send data through BUS.
  * @param  DevAddr : Device address on Bus.
  * @param  pData   : Pointer to data buffer to write
  * @param  Length  : Data Length
  * @retval STSAFEA_HW_OK   : on success
  * @retval STSAFEA_HW_NACK : on bus NACK
  * @retval STSAFEA_HW_ERR  : on bus error
  */
int32_t I2C_Send(uint16_t DevAddr, uint8_t *pData, uint16_t Length)
{
  int32_t ret;

  ret = BSP_I2C1_Send(DevAddr, pData, Length);
  if (ret == BSP_ERROR_BUS_ACKNOWLEDGE_FAILURE)
  {
    return STSAFEA_BUS_NACK;
  }

  if (ret == BSP_ERROR_PERIPH_FAILURE)
  {
    return STSAFEA_BUS_ERR;
  }

  return STSAFEA_BUS_OK;
}

/**
  * @brief  I2C_Recv
  *         Receive data through BUS.
  * @param  DevAddr Device address on Bus.
  * @param  Reg    The target register address to read
  * @param  pData  Pointer to data buffer to read
  * @param  Length Data Length
  * @retval BSP status
  */
int32_t I2C_Recv(uint16_t DevAddr, uint8_t *pData, uint16_t Length)
{
  int32_t ret;

  ret = BSP_I2C1_Recv(DevAddr, pData, Length);
  if (ret == BSP_ERROR_BUS_ACKNOWLEDGE_FAILURE)
  {
    return STSAFEA_BUS_NACK;
  }

  if (ret == BSP_ERROR_PERIPH_FAILURE)
  {
    return STSAFEA_BUS_ERR;
  }

  return STSAFEA_BUS_OK;
}

/**
  * @brief  StSafeA_HW_Probe
  *         Configure STSAFE IO and Bus operation functions to be implemented at User level
  * @param  Ctx the STSAFE IO context
  * @retval 0 in case of success, an error code otherwise
  */
int8_t StSafeA_HW_Probe(void *pCtx)
{
  STSAFEA_HW_t *HwCtx = (STSAFEA_HW_t *)pCtx;


  HwCtx->IOInit     = HW_IO_Init;
  HwCtx->BusInit    = I2C_Init;
  HwCtx->BusDeInit  = I2C_DeInit;
  HwCtx->BusSend    = I2C_Send;
  HwCtx->BusRecv    = I2C_Recv;
  HwCtx->CrcInit    = CRC16X25_Init;
  HwCtx->CrcCompute = CRC_Compute;
  HwCtx->TimeDelay  = HAL_Delay;
  HwCtx->DevAddr    = STSAFEA_DEVICE_ADDRESS;

  return STSAFEA_BUS_OK;
}


