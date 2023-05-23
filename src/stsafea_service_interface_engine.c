/**
  ******************************************************************************
  * @file    stsafea_service_interface_template.c
  * @author  SMD/AME application teams
  * @version V3.3.0
  * @brief   Service Interface file to support the hardware services required by the
  *          STSAFE-A Middleware and offered by the specific HW, Low Level library
  *          selected by the user. E.g.:
  *           + IOs
  *           + Communication Bus (e.g. I2C)
  *           + Timing delay
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
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include "stsafea_service.h"
#include "stsafea_interface_conf.h"
#include <string.h>
/* Private typedef -----------------------------------------------------------*/

#if defined (BUS_CONF_DEBUG)
#define BUS_CONF_Print(...) printf(__VA_ARGS__)
#else
#define BUS_CONF_Print(...)
#endif /* BUS_CONF_DEBUG */

/* Private define ------------------------------------------------------------*/

/* I2C address */
#ifndef STSAFEA_DEVICE_ADDRESS
#define STSAFEA_DEVICE_ADDRESS                    0x0020
#endif

#ifndef STSAFEA_DEFAULT_I2CBUS
#define STSAFEA_DEFAULT_I2CBUS "1"
#endif

/* Set to 1 to have CRC16_CCIT Table already calculated and placed in Flash as const. Set to zero to dynamically calculate it in RAM */
#define STSAFEA_USE_OPTIMIZATION_CRC_TABLE     1U

/* Private macro -------------------------------------------------------------*/

#define I2C_DELAY(x)  usleep((x) * 1000)

#ifdef _FAKT
/* Polling duration as count value for i2c operation. */
#define I2C_POLLING   ((uint32_t)7)
#else
/* Polling duration as count value for i2c operation. */
#define I2C_POLLING   ((uint32_t)4000)
#endif /* _FAKT */

#define STSAFE_A_CHECK_TXRX_SIZE(index, size)        \
{                                                     \
  if ((size + index ) > STSAFEA_BUFFER_MAX_SIZE)         \
  {                                                   \
    return 1;                                        \
  }                                                   \
}

/* Private variables ---------------------------------------------------------*/

/* File descriptor ID for I2C */
static int32_t _fd = -1;

/**
  * Table for the CRC16 X.25
  *   - Polynomial           : 0x1021
  *   - Degree of polynomial : 16
  *   - Generator polynomial : G(x) = x^16 + x^12 + x^5 + 1
  *   - Input order          : Reflected
  *   - Result order         : Reflected
  *   - Initial value        : 0xFFFF
  *   - Final XOR mask       : 0xFFFF
  */
#define STSAFEA_CRC16_X25_REFLECTED_LOOKUP_TABLE \
  0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF, 0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7, \
  0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E, 0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876, \
  0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD, 0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5, \
  0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C, 0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974, \
  0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB, 0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3, \
  0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A, 0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72, \
  0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9, 0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1, \
  0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738, 0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70, \
  0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF, \
  0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036, 0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E, \
  0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5, 0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD, \
  0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134, 0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C, \
  0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3, 0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB, \
  0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232, 0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A, \
  0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1, 0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9, \
  0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330, 0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78


/* Private function prototypes -----------------------------------------------*/

#if defined (BUS_CONF_DEBUG)
static char *Delta2Str(long delta, char *string, size_t string_size);
static char *Tag2Str(uint8_t tag);
static char *Cmd2Name(uint8_t cmd, uint8_t extra, char *string, size_t string_size);
static char *Cmac2Str(uint8_t cmd);
static char *Rmac2Str(uint8_t cmd);
static char *Secure2Str(uint8_t cmd);
static char *Cmd2Str(uint8_t cmd, uint8_t extra);
#endif
static int32_t CRC16X25_Init(void);
static uint32_t CRC_Compute(uint8_t *pData1, uint16_t Length1, uint8_t *pData2, uint16_t Length2);

int32_t StSafeA_HW_IO_Init(void);
void StSafeA_I2C_DELAY(uint32_t msDelay);
static const char *I2CBUS = STSAFEA_DEFAULT_I2CBUS;
int32_t StSafeA_Bus_Init(void);
int32_t StSafeA_Bus_DeInit(void);
int32_t StSafeA_Bus_Send(uint16_t DevAddr, uint8_t *pData, uint16_t Length);
int32_t  StSafeA_Bus_Recv(uint16_t DevAddr, uint8_t *pData, uint16_t Length);
/* public functions ---------------------------------------------------------*/
/**
  * @brief  Configure STSAFE IO and Bus operation functions to be implemented at User level
  * @param  Ctx the STSAFE IO context
  * @retval 0 in case of success, an error code otherwise
  */
int8_t StSafeA_HW_Probe(void *pCtx)
{
    STSAFEA_HW_t *myHwCtx = (STSAFEA_HW_t *)pCtx;

    myHwCtx->BusInit    = StSafeA_Bus_Init;
    myHwCtx->BusDeInit  = StSafeA_Bus_DeInit;
    myHwCtx->BusSend    = StSafeA_Bus_Send;
    myHwCtx->BusRecv    = StSafeA_Bus_Recv;
    myHwCtx->IOInit     = StSafeA_HW_IO_Init;
    myHwCtx->CrcInit    = CRC16X25_Init;
    myHwCtx->CrcCompute = CRC_Compute;
    myHwCtx->TimeDelay  = StSafeA_I2C_DELAY;
    myHwCtx->DevAddr    = STSAFEA_DEVICE_ADDRESS;

  return STSAFEA_BUS_OK;
}

/* Private functions ---------------------------------------------------------*/

/*
 * 
 * I2C functions
 * 
 */
int32_t StSafeA_Bus_Init(void)
{
    char name[16];

    snprintf(name, 16, "/dev/i2c-%s", I2CBUS);

    _fd = open(name, O_RDWR);

    if (_fd == -1)
    {
      BUS_CONF_Print("Unable to open I2C bus %s\n", name);
      _fd = -1;
    }

    return (0); /* Return 0 if success */
}

/* holder function, doing nothing, the engine should not shutdown the I2C Bus*/
int32_t StSafeA_Bus_DeInit(void)
{
    return (0);
}

/**
  * @brief  send data through I2C BUS.
  * @param  DevAddr Device address on Bus.
  * @param  Reg    The target register address to write
  * @param  pData  Pointer to data buffer to write
  * @param  Length Data Length
  * @retval STSAFEA_HW return status
  */
int32_t StSafeA_Bus_Send(uint16_t DevAddr, uint8_t *pData, uint16_t Length)
{
    int32_t status_code = STSAFEA_BUS_OK;
  
    /* set the I2C address, the calling function in stsafea_service.c shifted the address by 1 bit so we shifted it back here. */
    ioctl(_fd, I2C_SLAVE, DevAddr >> 1); 
    
    status_code = write(_fd, pData, Length);

    if ((status_code != Length) && (errno == EREMOTEIO ))
    {
      status_code = STSAFEA_BUS_NACK;
    }
    else if (status_code != Length)
    {
      status_code = STSAFEA_BUS_ERR;
    }
    else
    {
      status_code = STSAFEA_BUS_OK;
    }
  
    return status_code;
}

/**
  * @brief  Receive data through I2C BUS
  * @param  DevAddr Device address on Bus.
  * @param  Reg    The target register address to read
  * @param  pData  Pointer to data buffer to read
  * @param  Length Data Length
  * @retval STSAFEA_HW return status
  */
int32_t  StSafeA_Bus_Recv(uint16_t DevAddr, uint8_t *pData, uint16_t Length)
{
    int32_t status_code = STSAFEA_BUS_OK;

    /* set the I2C address, the calling function in stsafea_service.c shifted the address by 1 bit so we shifted it back here. */
    ioctl(_fd, I2C_SLAVE, DevAddr >> 1);
    
    status_code = read(_fd, pData, Length);

    if ((status_code != Length) && ((errno == EREMOTEIO) || (errno == ENXIO) ))
    {
      status_code = STSAFEA_BUS_NACK;
    }
    else if (status_code != Length)
    {
      status_code = STSAFEA_BUS_ERR;
    }
    else
    {
      status_code = STSAFEA_BUS_OK;
    }
    
    return status_code;
}

/* holder function, doing nothing since the platform should have initialized IOs already */
int32_t StSafeA_HW_IO_Init(void)
{
    return (0); /* Return 0 if success */
}

/* I2C delay function */
#include <time.h>
#include <errno.h>    
void StSafeA_I2C_DELAY(uint32_t msDelay)
{
  I2C_DELAY(msDelay);
#if 0
/* msleep(): Sleep for the requested number of milliseconds. */
    struct timespec ts;
    int res;

    if (msDelay < 0)
    {
        errno = EINVAL;
    }

    ts.tv_sec = msDelay / 1000;
    ts.tv_nsec = (msDelay % 1000) * 1000000;

    do {
        res = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,&ts, NULL);
    } while (res && errno == EINTR);
#endif
}


/*
 * 
 * CRC functions
 * 
 */

/**
  * @brief   StSafeA_Crc16_ccitt
  *          Computes the CRC16 CCITT over the data passed (header & data pointer).
  *
  * @param   Header : Payload's Header.
  * @param   pData  : Payload's data.
  * @param   Length : Length of payload's data.
  * @retval  uint16_t containing the calculated CRC
  */
static uint16_t StSafeA_Crc16_ccitt(uint8_t Header, uint8_t *pData, uint16_t Length)
{
#if (STSAFEA_USE_OPTIMIZATION_CRC_TABLE)
  static const uint16_t crc16_reflected_lookup_table[256] = {STSAFEA_CRC16_X25_REFLECTED_LOOKUP_TABLE};
#else
  static uint16_t crc16_reflected_lookup_table[256] = {0};
#endif /* STSAFEA_USE_OPTIMIZATION_CRC_TABLE */

  uint16_t crc = 0xFFFF;
  if (pData != NULL)
  {
    uint8_t ndx;
    uint16_t i;

#if (!STSAFEA_USE_OPTIMIZATION_CRC_TABLE)
    /* Instead of reflecting the data coming in, and the CRC coming in, and
       the CRC going out, simply reflect the polynomial and the operations.
       Only need to do that oncethrough the code.
       The reflected polynomial is 0x8408. */
    if (crc16_reflected_lookup_table[1] == 0x0000U)
    {
      uint16_t  remainder;
      for (int dividend = 0; dividend < 256; ++dividend)
      {
        remainder = dividend;
        for (uint8_t bit = 8; bit > 0; --bit)
        {
          if (remainder & 1)
          {
            remainder = (remainder >> 1) ^ 0x8408;
          }
          else
          {
            remainder = (remainder >> 1);
          }
        }
        crc16_reflected_lookup_table[dividend] = remainder;
      }
    }
#endif /* STSAFEA_USE_OPTIMIZATION_CRC_TABLE */

    ndx = (uint8_t)(0xFFU & (crc ^ Header));
    crc = (crc16_reflected_lookup_table[ndx] ^ 0xFFU);

    for (i = 0; i < Length; i++)
    {
      ndx = (uint8_t)(0xFFU & (crc ^ pData[i]));
      crc = (crc16_reflected_lookup_table[ndx] ^ (crc >> 8));
    }
  }

  return crc;
}

/**
  * @brief   CRC16X25_Init
  *          Initializes CRC X25.
  * @retval  BSP status
  */
int32_t CRC16X25_Init(void)
{
  return 0;
}

/**
  * @brief   Compute CRC
  *          Computes the CRC using software solution.
  *          CRC is computed firsly using 1st data starting with initialization value.
  *          CRC is computed secondly using 2nd data starting with the previously computed CRC.
  *
  * @param   pData1  : Pointer to 1st input data buffer.
  * @param   Length1 : Size of 1st input data buffer.
  * @param   pData2  : Pointer to 2nd input data buffer.
  * @param   Length2 : Size of 2nd input data buffer.
  * @retval  uint32_t CRC (returned value LSBs for CRC)
  */
uint32_t CRC_Compute(uint8_t *pData1, uint16_t Length1, uint8_t *pData2, uint16_t Length2)
{
  (void)Length1;
  uint16_t crc16 = 0;
  if ((pData1 != NULL) && (pData2 != NULL))
  {
    crc16 = StSafeA_Crc16_ccitt(pData1[0], pData2, Length2);

    crc16 = (uint16_t)SWAP2BYTES(crc16);
    crc16 ^= 0xFFFFU;
  }
  return (uint32_t)crc16;
}


/* 
 * 
 * Functions for value to string conversions 
 * 
 * 
 */
 
#if defined (BUS_CONF_DEBUG)
static char *Delta2Str(long delta, char *string, size_t string_size)
{
  long ms;
  long decimal;

  ms = delta/1000000;
  decimal = delta - (ms * 1000000);
  decimal /= 1000;

  memset(string, '\0', sizeof(string_size));
  snprintf(string, string_size, "%5ld.%03ld", ms, decimal);

  return string;
}


static char *Tag2Str(uint8_t tag)
{
  switch (tag)
  {
    case STSAFEA_TAG_ADMIN_BASE_KEY_SLOT         :
      return "ADMIN_BASE_KEY_SLOT_TAG";
      break;

    case STSAFEA_TAG_LOCAL_ENVELOPE_KEY_TABLE    :
      return "LOCAL_ENVELOPE_KEY_TABLE_TAG";
      break;

    case STSAFEA_TAG_LIFE_CYCLE_STATE            :
      return "LIFE_CYCLE_STATE_TAG";
      break;

    case STSAFEA_TAG_PASSWORD_SLOT               :
      return "PASSWORD_SLOT_TAG";
      break;

    case STSAFEA_TAG_I2C_PARAMETER               :
      return "I2C_PARAMETER_TAG";
      break;

    case STSAFEA_TAG_PRODUCT_DATA                :
      return "PRODUCT_DATA_TAG";
      break;

    case STSAFEA_TAG_DATA_PARTITION_CONFIGURATION:
      return "DATA_PARTITION_TAG";
      break;

    case STSAFEA_TAG_PRIVATE_KEY_SLOT            :
      return "PRIVATE_KEY_SLOT_TAG";
      break;

    case STSAFEA_TAG_PRIVATE_KEY_TABLE           :
      return "PRIVATE_KEY_TABLE_TAG";
      break;

    case STSAFEA_TAG_HOST_KEY_SLOT               :
      return "HOST_KEY_SLOT_TAG";
      break;

    case STSAFEA_TAG_COMMAND_AUTHORIZATION_CONFIGURATION     :
      return "COMMAND_AUTHORIZATION_CONFIGURATION_TAG";
      break;

    case STSAFEA_TAG_COMMAND_ACCESS_CONDITIONS               :
      return "COMMAND_ACCESS_CONDITIONS_TAG";
      break;

    case STSAFEA_TAG_COMMAND_HOST_ENCRYPTION_FLAGS           :
      return "COMMAND_HOST_ENCRYPTION_FLAGS_TAG";
      break;

  }

  return "UNKNOWN";
}

static char *Cmd2Name(uint8_t cmd, uint8_t extra, char *string, size_t string_size)
{
  memset(string, '\0', sizeof(string_size));

  switch (cmd)
  {
    case STSAFEA_CMD_ECHO:
      return "ECHO                     ";

    case STSAFEA_CMD_RESET:
      return "WARM_RESET               ";

    case STSAFEA_CMD_GENERATE_RANDOM:
      return "GENERATE_RANDOM          ";

    case STSAFEA_CMD_START_SESSION:
      return "START_SESSION            ";

    case STSAFEA_CMD_DECREMENT:
      return "DECREMENT                ";

    case STSAFEA_CMD_READ:
      return "READ                     ";

    case STSAFEA_CMD_UPDATE:
      return "UPDATE                   ";

    case STSAFEA_CMD_DELETE_KEY:
      return "DELETE_KEY               ";

    case STSAFEA_CMD_HIBERNATE:
      return "HIBERNATE                ";

    case STSAFEA_CMD_WRAP_LOCAL_ENVELOPE:
      return "WRAP_LOCAL_ENVELOPE      ";

    case STSAFEA_CMD_UNWRAP_LOCAL_ENVELOPE:
      return "UNWRAP_LOCAL_ENVELOPE    ";

    case STSAFEA_CMD_PUT_ATTRIBUTE:
      return "PUT_ATTIBUTE             ";

    case STSAFEA_CMD_GENERATE_KEY:
      return "GENERATE_KEY             ";

    case STSAFEA_CMD_QUERY:
      snprintf(string, string_size, "QUERY %-19s", Tag2Str(extra));
      return string;

    case STSAFEA_CMD_GENERATE_SIGNATURE:
      return "GENERATE_SIGNATURE       ";

    case STSAFEA_CMD_VERIFY_SIGNATURE:
      return "VERIFY_SIGNATURE         ";

    case STSAFEA_CMD_ESTABLISH_KEY:
      return "ESTABLISH_KEY            ";

    case STSAFEA_CMD_VERIFY_PASSWORD:
      return "VERIFY_PASSWORD          ";
  }

  return "UNKNOWN";
}

static char *Cmac2Str(uint8_t cmd)
{
  if (cmd & 0x80)
  {
    return " CMAC";
  }

  return "     ";
}

static char *Rmac2Str(uint8_t cmd)
{
  if (cmd & 0x40)
  {
    return " RMAC";
  }

  return "     ";
}

static char *Secure2Str(uint8_t cmd)
{
  if (cmd & 0x20)
  {
    return " SCCH";
  }

  return "     ";
}

static char *Cmd2Str(uint8_t cmd, uint8_t extra)
{
  static char str[256];
  char cmd_name[30];

  memset(str, '\0', sizeof(str));

  snprintf(str, 256, "%s 0x%02x %s%s%s",
           Cmd2Name(cmd & 0x1F, extra, &cmd_name[0], sizeof(cmd_name)),
           cmd & 0x1F, Cmac2Str(cmd), Rmac2Str(cmd), Secure2Str(cmd));

  return str;
}
#endif
/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
