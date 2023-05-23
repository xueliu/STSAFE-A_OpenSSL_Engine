/**
  ******************************************************************************
  * @file    stsafea_conf.h
  * @author  SMD application team
  * @version V3.3.6
  * @brief   STSAFE-A1XX Middleware configuration file
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
#ifndef STSAFEA_CONF_H
#define STSAFEA_CONF_H


#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/

/** @addtogroup STSAFEA
  * @{
  */


/** @defgroup STSAFEA_CONFIG
  * @{
  */


/** @defgroup STSAFEA_CONFIG_Exported_Constants
  * @{
  */

/* Set to 1 to optimize RAM usage. If set to 1 the StSafeA_Handle_t.InOutBuffer used through the Middleware APIs
   is shared
   with the application between each command & response. It means that every time the MW API returns a TLVBuffer pointer,
   it returns in fact a pointer to the shared StSafeA_Handle_t.InOutBuffer.
   As consequence the user shall copy data from given pointer into variable defined by himself in case data need
   to be stored.
   If set to 0 the user must specifically allocate (statically or dynamically) a right sized buffer to be passed as
   parameter
   to the Middleware command API */
#define STSAFEA_USE_OPTIMIZATION_SHARED_RAM             0U

/* Set to 1 to optimize RAM/Flash usage, when Host MAC and encryption features are not required
  (eg. Authentication use case) */
#define STSAFEA_USE_OPTIMIZATION_NO_HOST_MAC_ENCRYPT    0U

/* Set to 1 to expanse the "assert_param" macro in the STSAFE middleware code */
#define STSAFEA_USE_FULL_ASSERT                         0U

#ifdef STSAFE_A100
/* Set to 1 in order to use Signature Sessions.
   Set to 0 to optimize code/memory size otherwise */
#define USE_SIGNATURE_SESSION                           1U
#endif /* STSAFE_A100 */

/* To optimize I2C Polling for STSAFE functions */
/* Max I2C polling delay in ms */
/*#define STSAFEA_I2C_POLLING_MAX              2500U */
/* I2C polling step in ms */
/*#define STSAFEA_I2C_POLLING_STEP                3U */

/**
  * @}
  */


/** @defgroup STSAFEA_INTERFACE_Exported_Macros
  * @{
  */

/* Weak function definition. A different __weak function definition might be needed for different platforms */
#if defined ( __GNUC__ ) && !defined (__CC_ARM) /* GNU Compiler */
#ifndef __weak
#define __weak   __attribute__((weak))
#endif /* __weak */
#endif /* __GNUC__ */

/* Endianness bytes swap */
#if defined ( __ICCARM__ )
#include "intrinsics.h"
#define SWAP2BYTES(x)    __REV16(x)            /*!< 16-bits Big-Little endian bytes swap */
#define SWAP4BYTES(x)    __REV(x)              /*!< 32-bits Big-Little endian bytes swap */
#elif defined ( __CC_ARM )
#include <stdint.h>
static __inline __asm uint32_t __rev16(uint32_t value)
{
  rev16 r0, r0
  bx lr
}
#define SWAP2BYTES(x)    __rev16(x)            /*!< 16-bits Big-Little endian bytes swap */
#define SWAP4BYTES(x)    __rev(x)              /*!< 32-bits Big-Little endian bytes swap */
#elif defined( __ARMCC_VERSION ) && ( __ARMCC_VERSION >= 6010050 )
#define SWAP2BYTES(x)    __builtin_bswap16(x)  /*!< 16-bits Big-Little endian bytes swap */
#define SWAP4BYTES(x)    __builtin_bswap32(x)  /*!< 32-bits Big-Little endian bytes swap */
#elif defined ( __GNUC__ )
#define SWAP2BYTES(x)    __builtin_bswap16(x)  /*!< 16-bits Big-Little endian bytes swap */
#define SWAP4BYTES(x)    __builtin_bswap32(x)  /*!< 32-bits Big-Little endian bytes swap */
#endif /* __ICCARM__  __CC_ARM  __ARMCC_VERSION && __ARMCC_VERSION >= 6010050  __GNUC__ */

/**
  * @}
  */


/** @defgroup STSAFEA_CONFIG_Exported_Macros
  * @{
  */

#if (STSAFEA_USE_FULL_ASSERT)
#include <stdint.h>

/**
  * @brief  The assert_param macro is used for function's parameters check.
  * @param  expr: If expr is false, it calls assert_failed function
  *         which reports the name of the source file and the source
  *         line number of the call that failed.
  *         If expr is true, it returns no value.
  * @retval None
  */
#define stsafea_assert_param(expr) ((expr) ? (void)0U : stsafea_assert_failed((uint8_t *)__FILE__, __LINE__))
/* Exported functions ------------------------------------------------------- */
void stsafea_assert_failed(uint8_t *file, uint32_t line);
#else
#define stsafea_assert_param(expr) ((void)0U)
#endif /* USE_FULL_ASSERT */
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
#endif

#endif /* STSAFEA_CONF_H */

