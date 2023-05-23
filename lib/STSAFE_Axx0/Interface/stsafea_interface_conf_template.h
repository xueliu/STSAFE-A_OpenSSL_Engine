/**
  ******************************************************************************
  * @file    stsafea_interface_conf.h
  * @author  SMD application team
  * @version V3.3.6
  * @brief   STSAFE-A Interface header file for application customization and use
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
#ifndef STSAFEA_INTERFACE_CONF_H
#define STSAFEA_INTERFACE_CONF_H


#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/

/** @addtogroup STSAFEA
  * @{
  */


/** @defgroup STSAFEA_INTERFACE
  * @{
  */


/** @defgroup STSAFEA_INTERFACE_Exported_Constants
  * @{
  */
/* Set to 1 if Host Keys have previously been stored in Flash (e.g. through the SDK Pairing Application)
   and must be retrieved from the MCU Flash. Set to 0 otherwise to use static keys values.
   This is used just as example in order to support static keys values (mainly
   for debugging purpose ) or switch to the right and proper way to retrieve the keys */
#define USE_PRE_LOADED_HOST_KEYS                1U

/* Include for MCU definition platform */
#define MCU_PLATFORM_INCLUDE                    "stm32l4xx.h"

/* Include for BUS definition platform */
#define MCU_PLATFORM_BUS_INCLUDE                "stm32l4xx_nucleo_bus.h"

/* Include for BUS definition platform */
#define MCU_PLATFORM_CRC_INCLUDE                "stm32l4xx_nucleo_crc.h"
/**
  * @}
  */


/** @defgroup STSAFEA_INTERFACE_Exported_Macros
  * @{
  */

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

#endif /* STSAFEA_INTERFACE_CONF_H */

