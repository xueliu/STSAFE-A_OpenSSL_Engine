/**
  ******************************************************************************
  * @file    stsafeaxxx.h
  * @author  SMD application team
  * @version V3.3.6
  * @brief   Header file to select the specific STSAFE_A1xx device.
  *          Used by the Middleware and by the target application.
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
#ifndef STSAFEAxxx_H
#define STSAFEAxxx_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/* Includes ------------------------------------------------------------------*/
#if defined(STSAFE_A100)
#include "stsafea100.h"
#elif defined(STSAFE_A110)
#include "stsafea110.h"
#else
#error "Please select first the target STSAFE_A1xx device used in your application (in stafe_axxx.h file)"
#endif /* STSAFE_A100 - STSAFE_A110 */


/** @addtogroup STSAFE_A1XX_DEVICE_DEF_MACRO_TYPES
  * @{
  */


/** @addtogroup DEVICE_STSAFE_A1xx
  * @{
  */


/* Exported macros -----------------------------------------------------------*/
/** @addtogroup STSAFE_A1xx_Exported_Macros
  * @{
  */

/* Big-Little endian bytes swap implementation if not already implemented using compiler/platform dependent optimized
   instructions (see stsafea_conf_template.h) */
#if !defined(SWAP2BYTES)
#define SWAP2BYTES(x)    (((x) & 0x00FFU) << 8) | (((x) & 0xFF00U) >> 8)  /*!< 16-bits Big-Little endian bytes swap */
#endif /* SWAP2BYTES */
#if !defined(SWAP4BYTES)
/*!< 32-bits Big-Little endian bytes swap */
#define SWAP4BYTES(x)    (((x)>>24) & 0xFFU) | (((x)<<8) & 0xFF0000U) |(((x)>>8) & 0xFF00U) | (((x)<<24U) & 0xFF000000U)
#endif /* SWAP4BYTES */

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

#endif /* STSAFEAxxx_H */



