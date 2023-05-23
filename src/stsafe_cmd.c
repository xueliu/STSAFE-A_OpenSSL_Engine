/**
 *********************************************************************************************
 * @file    stsafe_cmd.c
 * @author  SMD application team
 * @version V1.0.1
 * @date    08-July-2020
 * @brief   Openssl STSAFE Engine dealing with engine cmds
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
/* Includes ------------------------------------------------------------------*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include "openssl/bn.h"
#include "openssl/sha.h"
#include "openssl/pem.h"
#include "openssl/opensslv.h"

#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#include <openssl/rand.h>
#include "openssl/ossl_typ.h"

#include "stsafe_init.h"
#include "stsafe_api.h"
#include "stsafea_types.h"
#include "stsafea_core.h"
#include "stsafea_conf.h"
#include "stsafea_crypto.h"
#include "stsafea_service.h"
#include "stsafea_interface_conf.h"
#include "stsafe_a_configuration.h"

/* private data */
typedef enum QueryIdx_e
{
    DataPartitionQuery,
    ProductDataQuery,
    I2cParameterQuery,
    LifeCycleStateQuery,
    HostKeySlotQuery,
    LocalEnvelopeKeySlotQuery,
    PublicKeySlotQuery,
    CommandAuthorizationConfigurationQuery,
    EndQueryList
} QueryIdx_t;

#define MAX_READ_UPDATE_CONTENT (STSAFEA_BUFFER_DATA_CONTENT_SIZE - 4)

static const char *QueryStr[EndQueryList] =
{
    "DataPartition",
    "ProductData",
    "I2cParameter",
    "LifeCycleState",
    "HostKeySlot",
    "LocalEnvelopeKeySlot",
    "PublicKeySlot",
    "CommandAuthorizationConfiguration"
};

const ENGINE_CMD_DEFN stsafe_cmd_defns[] = {
    {
        STSAFE_CMD_GET_PRODUCT_DATA,
        "PRODUCTINFO",
        "Get STSAFE Product version ",
        ENGINE_CMD_FLAG_NO_INPUT
    },
    {
        STSAFE_CMD_GET_DEVICE_CERT,
        "GET_DEVICE_CERT",
        "Get device certificate from hardware and stores in the provided filename",
        ENGINE_CMD_FLAG_STRING
    },
    {
        STSAFE_CMD_SET_SIG_KEY_SLOT,
        "SET_SIG_KEY_SLOT",
        "Set the slot that the engine will use for signature generation (default 1)",
        ENGINE_CMD_FLAG_NUMERIC
    },
    {
        STSAFE_CMD_SET_GEN_KEY_SLOT,
        "SET_GEN_KEY_SLOT",
        "Set the slot that the engine will use for key generation (default 255)",
        ENGINE_CMD_FLAG_NUMERIC
    },
    {
        STSAFE_CMD_SET_MEMORY_REGION,
        "SET_MEMORY_REGION",
        "Set the memory region to be used for writing of certifiate (default 1)",
        ENGINE_CMD_FLAG_NUMERIC
    },
    {
        STSAFE_CMD_WRITE_DEVICE_CERT,
        "WRITE_CERTIFICATE",
        "Write certificate given in filename (DER format) to memory region",
        ENGINE_CMD_FLAG_STRING
    },
    {
        STSAFE_CMD_RESET,
        "RESET_ENGINE",
        "Reset the Stsafe to default and call the driver init function",
        ENGINE_CMD_FLAG_NO_INPUT
    },
    {
        STSAFE_CMD_ECHO,
        "COMMAND_ECHO",
        "Echo back the given string",
        ENGINE_CMD_FLAG_STRING
    },
    {
        STSAFE_CMD_HIBERNATE,
        "ENGINE_HIBERNATE",
        "Put STSafe in Hibernate mode",
        ENGINE_CMD_FLAG_NUMERIC
    },
    {
        STSAFE_CMD_VERIFYPASSWORD,
        "ENGINE_VERIFYPASSWORD",
        "Verify the password based on the password stored in the hardware",
        ENGINE_CMD_FLAG_STRING
    },
    {
        STSAFE_CMD_QUERY,
        "ENGINE_QUERY",
        "Query the requested setting on the STSAFE device",
        ENGINE_CMD_FLAG_STRING
    },
    {
      STSAFE_CMD_GET_SERIAL_NUMBER,
      "GETSERIALNUMBER",
      "Get STSAFE Serial Number",
      ENGINE_CMD_FLAG_NO_INPUT,
    },
    /* Structure has to end with a null element */
    {
        0,
        NULL,
        NULL,
        0
    }
};

static int queryDataPartition(StSafeA_Handle_t *pStSafeA);
static int queryProductData(StSafeA_Handle_t *pStSafeA);
static int queryI2cParameter(StSafeA_Handle_t *pStSafeA);
static int queryLifeCycleState(StSafeA_Handle_t *pStSafeA);
static int queryHostKeySlot(StSafeA_Handle_t *pStSafeA);
static int queryLocalEnvelopeKeySlot(StSafeA_Handle_t *pStSafeA);
static int queryPublicKeySlot(StSafeA_Handle_t *pStSafeA);
static int queryCommandAuthorizationConfiguration(StSafeA_Handle_t *pStSafeA);
static int writeCertificate(StSafeA_Handle_t *pStSafeA, char *filename);
static int readCertificate(StSafeA_Handle_t *pStSafeA, char *filename);
static void dumpProductData(const StSafeA_ProductDataBuffer_t *const productData);

static int queryDataPartition(StSafeA_Handle_t *pStSafeA)
{
    char                   opensslerrbuff[1024];
    long int               opensslerr   = 0;
    uint8_t                zoneMaxNum   = 0;
    StSafeA_ResponseCode_t statusCode   = STSAFEA_INVALID_PARAMETER;

    StSafeA_DataPartitionBuffer_t         dataPartInfo = { 0 };
    StSafeA_ZoneInformationRecordBuffer_t tempZinfo    = { 0 };
    dataPartInfo.pZoneInfoRecord                       = &tempZinfo;
    memset(opensslerrbuff, 0x00, 1024 * sizeof(char));

    CMD_FPRINTF(stdout, "STSAFE-A1x0 Data Partition Information\n");
    CMD_FPRINTF(stdout, "--------------------------------------\n");

    /* First get the number of records */
    statusCode = StSafeA_DataPartitionQuery(pStSafeA,
                                            zoneMaxNum,
                                            &dataPartInfo,
                                            STSAFEA_MAC_NONE);

    if (statusCode == STSAFEA_INVALID_RESP_LENGTH) {
        /* length is given to us so we can allocate memory for data records */
        zoneMaxNum                 = dataPartInfo.NumberOfZones;
        dataPartInfo.NumberOfZones = 0;
        dataPartInfo.Length        = 0;

        dataPartInfo.pZoneInfoRecord = OPENSSL_malloc(zoneMaxNum * sizeof(StSafeA_ZoneInformationRecordBuffer_t));
        if (dataPartInfo.pZoneInfoRecord == NULL) {
            DEBUG_FPRINTF(stderr, "STSAFE> %s: OPENSSL_malloc failed\n", __func__);
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
            }
            statusCode = STSAFEA_INVALID_PARAMETER;
        }
    }

    if (statusCode == STSAFEA_INVALID_RESP_LENGTH) {
        statusCode = StSafeA_DataPartitionQuery(pStSafeA,
                                                zoneMaxNum,
                                                &dataPartInfo,
                                                STSAFEA_MAC_NONE);
        if (statusCode == STSAFEA_OK) {
            for (uint32_t i = 0 ; i < dataPartInfo.NumberOfZones; i++) {
                CMD_FPRINTF(stdout, "Index                 : %02d\n", dataPartInfo.pZoneInfoRecord[i].Index);
                CMD_FPRINTF(stdout, "ZoneType              : %02d\n", dataPartInfo.pZoneInfoRecord[i].ZoneType);
                CMD_FPRINTF(stdout, "ReadAcChangeRight     : 0x%02x\n", dataPartInfo.pZoneInfoRecord[i].ReadAcChangeRight);
                CMD_FPRINTF(stdout, "ReadAccessCondition   : 0x%02x\n", dataPartInfo.pZoneInfoRecord[i].ReadAccessCondition);
                CMD_FPRINTF(stdout, "UpdateAcChangeRight   : 0x%02x\n", dataPartInfo.pZoneInfoRecord[i].UpdateAcChangeRight);
                CMD_FPRINTF(stdout, "UpdateAccessCondition : 0x%02x\n", dataPartInfo.pZoneInfoRecord[i].UpdateAccessCondition);
                CMD_FPRINTF(stdout, "DataSegmentLength     : %04d bytes\n", dataPartInfo.pZoneInfoRecord[i].DataSegmentLength);
                if (dataPartInfo.pZoneInfoRecord->ZoneType & 0x1) {
                    CMD_FPRINTF(stdout, "OneWayCounter         : %08d\n", dataPartInfo.pZoneInfoRecord[i].OneWayCounter);
                }
            }
        }
    }
    if (dataPartInfo.pZoneInfoRecord != NULL) {
        OPENSSL_free(dataPartInfo.pZoneInfoRecord);
    }

    return statusCode;
}

static int queryProductData(StSafeA_Handle_t *pStSafeA)
{
    StSafeA_ResponseCode_t       statusCode = STSAFEA_INVALID_PARAMETER;
    StSafeA_ProductDataBuffer_t  queryData  = { 0 };

    statusCode = StSafeA_ProductDataQuery(pStSafeA,
                                          &queryData,
                                          STSAFEA_MAC_NONE);

    if (statusCode == 0) {
        dumpProductData(&queryData);
    }

    return statusCode;
}

static int queryI2cParameter(StSafeA_Handle_t *pStSafeA)
{
    StSafeA_ResponseCode_t       statusCode = STSAFEA_INVALID_PARAMETER;
    StSafeA_I2cParameterBuffer_t i2cInfo    = { 0 };

    statusCode = StSafeA_I2cParameterQuery(pStSafeA,
                                           &i2cInfo,
                                           STSAFEA_MAC_NONE);
    if (statusCode == STSAFEA_OK) {
        CMD_FPRINTF(stdout, "STSAFE-A1x0 I2C Information\n");
        CMD_FPRINTF(stdout, "---------------------------\n");
        CMD_FPRINTF(stdout, "I2cAddress         : 0x%02x\n", i2cInfo.I2cAddress);
        CMD_FPRINTF(stdout, "LowPowerModeConfig : 0x%02x\n", i2cInfo.LowPowerModeConfig);
        CMD_FPRINTF(stdout, "LockConfig         : 0x%02x\n", i2cInfo.LockConfig);
    }
    return statusCode;
}

static int queryLifeCycleState(StSafeA_Handle_t *pStSafeA)
{
    StSafeA_ResponseCode_t         statusCode = STSAFEA_INVALID_PARAMETER;
    StSafeA_LifeCycleStateBuffer_t lifeInfo   = { 0 };

    statusCode = StSafeA_LifeCycleStateQuery(pStSafeA,
                                             &lifeInfo,
                                             STSAFEA_MAC_NONE);
    if (statusCode == STSAFEA_OK) {
        CMD_FPRINTF(stdout, "STSAFE-A1x0 Lifecycle Information\n");
        CMD_FPRINTF(stdout, "---------------------------------\n");
        CMD_FPRINTF(stdout, "LifeCycleStatus    : 0x%02x\n", lifeInfo.LifeCycleStatus);
    }
    return statusCode;
}

static int queryHostKeySlot(StSafeA_Handle_t *pStSafeA)
{
    StSafeA_ResponseCode_t      statusCode  = STSAFEA_INVALID_PARAMETER;
    StSafeA_HostKeySlotBuffer_t hostKeyInfo = { 0 };

    statusCode = StSafeA_HostKeySlotQuery(pStSafeA,
                                          &hostKeyInfo,
                                          STSAFEA_MAC_NONE);
    if (statusCode == STSAFEA_OK) {
        CMD_FPRINTF(stdout, "STSAFE-A1x0 Host Key Slot Information\n");
        CMD_FPRINTF(stdout, "-------------------------------------\n");
        CMD_FPRINTF(stdout, "HostKeyPresenceFlag        : 0x%02x\n", hostKeyInfo.HostKeyPresenceFlag);
        if (hostKeyInfo.HostKeyPresenceFlag != 0) {
            CMD_FPRINTF(stdout, "HostCMacSequenceCounter    : %d\n", hostKeyInfo.HostCMacSequenceCounter);
        }
    }
    return statusCode;
}

static int queryLocalEnvelopeKeySlot(StSafeA_Handle_t *pStSafeA)
{
    StSafeA_ResponseCode_t                            statusCode      = STSAFEA_INVALID_PARAMETER;
    StSafeA_LocalEnvelopeKeyTableBuffer_t             envKeyTable     = { 0 };
    StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t envKeySlot0Info = { 0 };
    StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t envKeySlot1Info = { 0 };

    statusCode = StSafeA_LocalEnvelopeKeySlotQuery(pStSafeA,
                                                   &envKeyTable,
                                                   &envKeySlot0Info,
                                                   &envKeySlot1Info,
                                                   STSAFEA_MAC_NONE);
    if (statusCode == STSAFEA_OK) {
        CMD_FPRINTF(stdout, "STSAFE-A1x0 Local Envelope Key Slot Information\n");
        CMD_FPRINTF(stdout, "-----------------------------------------------\n");
        CMD_FPRINTF(stdout, "NumberOfSlots    : %d\n", envKeyTable.NumberOfSlots);
        if (envKeyTable.NumberOfSlots >= 1) {
            CMD_FPRINTF(stdout, "SlotNumber       : %d\n", envKeySlot0Info.SlotNumber);
            CMD_FPRINTF(stdout, "PresenceFlag     : %d\n", envKeySlot0Info.PresenceFlag);
            CMD_FPRINTF(stdout, "KeyLength        : %s\n",
                    envKeySlot0Info.KeyLength ? "AES 256 bit" : "AES 128 bit");
            if (envKeyTable.NumberOfSlots == 2) {
                CMD_FPRINTF(stdout, "SlotNumber       : %d\n", envKeySlot1Info.SlotNumber);
                CMD_FPRINTF(stdout, "PresenceFlag     : %d\n", envKeySlot1Info.PresenceFlag);
                CMD_FPRINTF(stdout, "KeyLength        : %s\n",
                        envKeySlot0Info.KeyLength ? "AES 256 bit" : "AES 128 bit");
            }
        }
    }
    return statusCode;
}

static int queryPublicKeySlot(StSafeA_Handle_t *pStSafeA)
{
    /* No lower layer driver at present */
    (void)pStSafeA;
    CMD_FPRINTF(stdout, "STSAFE> %s: Function not supported at this time\n", __func__);
    return STSAFEA_OK;
}

static int queryCommandAuthorizationConfiguration(StSafeA_Handle_t *pStSafeA)
{
    char                   opensslerrbuff[1024];
    long int               opensslerr     = 0;
    StSafeA_ResponseCode_t statusCode     = STSAFEA_INVALID_PARAMETER;
    uint8_t                numCmdAuthRecs = 0;

    StSafeA_CommandAuthorizationRecordBuffer_t        cmdAuthRec    = { 0 };
    StSafeA_CommandAuthorizationConfigurationBuffer_t cmdAuthConfig = { 0 };

    cmdAuthConfig.pCommandAuthorizationRecord = &cmdAuthRec;
    memset(opensslerrbuff, 0x00, 1024 * sizeof(char));

    /* get number of records to process */
    statusCode = StSafeA_CommandAuthorizationConfigurationQuery(pStSafeA,
                                                                numCmdAuthRecs,
                                                                &cmdAuthConfig,
                                                                STSAFEA_MAC_NONE);

    if (statusCode == STSAFEA_INVALID_RESP_LENGTH) {
        /* length is given to us so we can allocate memory for data records */
        numCmdAuthRecs              = cmdAuthConfig.CommandAuthorizationRecordNumber;
        cmdAuthConfig.Length        = 0;

        cmdAuthConfig.pCommandAuthorizationRecord =
                OPENSSL_malloc(numCmdAuthRecs * sizeof(StSafeA_CommandAuthorizationRecordBuffer_t));

        if (cmdAuthConfig.pCommandAuthorizationRecord == NULL) {
            DEBUG_FPRINTF(stderr, "STSAFE> %s: OPENSSL_malloc failed\n", __func__);
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
            }
            statusCode = STSAFEA_INVALID_PARAMETER;
        }
    }

    if (statusCode == STSAFEA_INVALID_RESP_LENGTH) {
        CMD_FPRINTF(stdout, "STSAFE-A1x0 Command Authorization Information\n");
        CMD_FPRINTF(stdout, "---------------------------------------------\n");

        statusCode = StSafeA_CommandAuthorizationConfigurationQuery(pStSafeA,
                                                                    numCmdAuthRecs,
                                                                    &cmdAuthConfig,
                                                                    STSAFEA_MAC_NONE);
        if (statusCode == STSAFEA_OK) {
            CMD_FPRINTF(stdout, "ChangeRight                      : 0x%02x\n", cmdAuthConfig.ChangeRight);
            CMD_FPRINTF(stdout, "CommandAuthorizationRecordNumber : %d\n", cmdAuthConfig.CommandAuthorizationRecordNumber);

            for (uint32_t i = 0 ; i < cmdAuthConfig.CommandAuthorizationRecordNumber; i++) {
                CMD_FPRINTF(stdout, "Record                           : %d\n", i);
                CMD_FPRINTF(stdout, "CommandCode                      : 0x%02x\n", cmdAuthConfig.pCommandAuthorizationRecord[i].CommandCode);
                CMD_FPRINTF(stdout, "CommandAC                        : 0x%02x\n", cmdAuthConfig.pCommandAuthorizationRecord[i].CommandAC);
                CMD_FPRINTF(stdout, "HostEncryptionFlags              : 0x%02x\n", cmdAuthConfig.pCommandAuthorizationRecord[i].HostEncryptionFlags);
            }
        }
    }
    if (cmdAuthConfig.pCommandAuthorizationRecord != NULL) {
        OPENSSL_free(cmdAuthConfig.pCommandAuthorizationRecord);
    }

    return statusCode;
}

static int writeCertificate(StSafeA_Handle_t *pStSafeA, char *filename)
{
    char                opensslerrbuff[1024];
    unsigned long       opensslerr      = 0;
    BIO                *inbio           = NULL;
    uint16_t            certificateSize = 0;
    uint32_t       len             = 0;
    int32_t        StatusCode      = STSAFEA_OK;
    uint32_t       numBytesRead    = 0;
    uint32_t       offsetBytes     = 0;
    uint32_t       numWrites       = 0;
    uint32_t       finalBytes      = 0;
    StSafeA_LVBuffer_t  stsWrite;

    memset(opensslerrbuff, 0x00, 1024 * sizeof(char));
    memset(&stsWrite, 0x00, sizeof(StSafeA_LVBuffer_t));
    stsWrite.Data = OPENSSL_malloc(STSAFEA_BUFFER_MAX_SIZE);
    if(stsWrite.Data == NULL) {
        DEBUG_FPRINTF(stderr, "STSAFE> %s: OPENSSL_malloc failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        StatusCode = STSAFEA_INVALID_PARAMETER;
    }

    if (StatusCode == STSAFEA_OK) {
        inbio = BIO_new_file((char *)filename, "r");
            if (inbio == NULL) {
                opensslerr = ERR_get_error();
                DEBUG_FPRINTF(stderr, "STSAFE> %s: BIO_new_file %s failed\n", __func__, filename);
                if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                    DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
                }
            StatusCode = STSAFEA_INVALID_PARAMETER;
        }
        }

    if (StatusCode == STSAFEA_OK) {
            /* Read in first four bytes of DER file to get length */
            len = BIO_read(inbio, &stsWrite.Data[0], 4);
            if (len != 4) {
                opensslerr = ERR_get_error();
                DEBUG_FPRINTF(stderr, "STSAFE> %s: BIO_read failed\n", __func__);
                if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                    DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
                }
            StatusCode = STSAFEA_INVALID_PARAMETER;
        }
            }

    if (StatusCode == STSAFEA_OK) {
            /* check first byte is 0x30 SEQUENCE and SEQUENCE OF tag */
            if (stsWrite.Data[0] != 0x30) {
                DEBUG_FPRINTF(stderr, "STSAFE> %s: Invalid DER file format, first tag is not SEQUENCE (0x30)\n", __func__);
            StatusCode = STSAFEA_INVALID_PARAMETER;
        }
            }

    if (StatusCode == STSAFEA_OK) {
            /* calculate size of file to read, length type will be either 0x81 or 0x82 */
            switch (stsWrite.Data[1])
            {
                case 0x81:
                    certificateSize = stsWrite.Data[2] + 3;
                    break;

                case 0x82:
                    certificateSize = (((uint16_t)stsWrite.Data[2]) << 8) + stsWrite.Data[3] + 4;
                    break;

                default:
                    if (stsWrite.Data[1] < 0x81){
                        certificateSize = stsWrite.Data[1];
                    }
                    break;
            }

            /* read in full certificate */
            stsWrite.Data[0] = 0x00;
            stsWrite.Data[1] = 0x00;
            stsWrite.Data[2] = 0x00;
            stsWrite.Data[3] = 0x00;

        /* calculate number of I2C writes needed */
        numWrites  = certificateSize/MAX_READ_UPDATE_CONTENT;
        finalBytes = certificateSize - (numWrites * MAX_READ_UPDATE_CONTENT);
        if (finalBytes) {
            numWrites++;
        }
        numBytesRead = MAX_READ_UPDATE_CONTENT;

        DEBUG_FPRINTF(stdout, "STSAFE> %s: certificateSize %d numWrites %d finalBytes %d\n",
                __func__, certificateSize, numWrites, finalBytes);

            BIO_reset(inbio);

        for (uint32_t writeNum = 0; writeNum < numWrites; writeNum++) {
            if ( (writeNum + 1) == numWrites) {
                numBytesRead = finalBytes; 
            }

            /* Read in numBytes of data to write */
            len = BIO_read(inbio, &stsWrite.Data[0], numBytesRead);
            if (len != numBytesRead) {
                opensslerr = ERR_get_error();
                DEBUG_FPRINTF(stderr, "STSAFE> %s: BIO_read failed number of bytes recv %d, expected %d\n",
                        __func__, len, numBytesRead);
                if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                    DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
                }
                StatusCode = STSAFEA_INVALID_PARAMETER;
            }

            if (StatusCode == STSAFEA_OK) {
            stsWrite.Length = len;
            DEBUG_FPRINTF(stdout, "STSAFE> %s: About to write certificate %d bytes offset %d in secure memory\n", __func__, len, offsetBytes);
            StatusCode = StSafeA_Update(pStSafeA,
                                        0,
                                        0,
                                        STSAFEA_AC_ALWAYS,
                                        0,
                                        stsafe_memory_region,
                                            offsetBytes,
                                        &stsWrite,
                                        STSAFEA_MAC_NONE);

                if (StatusCode != STSAFEA_OK) {
                DEBUG_FPRINTF(stderr, "STSAFE> %s: StSafeA_Update failed with error code 0x%02x\n", __func__, StatusCode);
                    writeNum   = numWrites;
                    StatusCode = STSAFEA_INVALID_PARAMETER;
                }
                offsetBytes = offsetBytes + numBytesRead;
            }
        }
    }
    return StatusCode;
}

static int32_t readCertificate(StSafeA_Handle_t *pStSafeA, char *filename)
{
    char      opensslerrbuff[1024];

    long int  opensslerr      = 0;
    size_t    certificateSize = 0;
    BIO      *outbio          = NULL;
    X509     *x               = NULL;
    uint8_t  *certRawStart    = NULL;
    uint8_t  *certRawCurr     = NULL;
    int32_t   StatusCode      = STSAFEA_OK;
    uint32_t  numBytesRead    = 0;
    uint32_t  offsetBytes     = 0;
		uint32_t  numReads        = 0;
		uint32_t  finalBytes      = 0;

		memset(opensslerrbuff, 0x00, 1024 * sizeof(char));

		StatusCode = stsafe_read_certificate(stsafe_memory_region, &certRawStart, &certificateSize);
		if (StatusCode == STSAFEA_OK) {
			DEBUG_FPRINTF(stdout, "STSAFE> %s: Device certificate size: %d\n", __func__, certificateSize);
			DEBUG_FPRINTF(stdout, "STSAFE> %s: Device certificate     : ", __func__);
			for(uint32_t i = 0; i < certificateSize; i++) {
				DEBUG_FPRINTF(stdout, "%02x", *(certRawStart + i));
			}
			DEBUG_FPRINTF(stdout, "\n");

			certRawCurr = certRawStart;
			x  = d2i_X509(NULL, (const unsigned char **)&certRawCurr, certificateSize);
			if (x == NULL) {
				opensslerr = ERR_get_error();
				DEBUG_FPRINTF(stderr, "STSAFE> %s: d2i_X509 failed\n", __func__);
				if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
					DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
				}
				OPENSSL_free(certRawStart);
				StatusCode = STSAFEA_INVALID_PARAMETER;
			}

			if ((StatusCode == STSAFEA_OK) && (filename != NULL)) {
				DEBUG_FPRINTF(stdout, "STSAFE> %s: Store the certificate to %s\n", __func__, (char *)filename);
				outbio = BIO_new_file((char *)filename, "w");
				if (outbio == NULL) {
					opensslerr = ERR_get_error();
					DEBUG_FPRINTF(stderr, "STSAFE>%s: BIO_new_file %s failed\n", __func__, (char *)filename);
					if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
						DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
					}
					OPENSSL_free(certRawStart);
					X509_free(x);
					StatusCode = STSAFEA_INVALID_PARAMETER;
				}
			}

			if (StatusCode == STSAFEA_OK) {
				if (! PEM_write_bio_X509(outbio, x)) {
					opensslerr = ERR_get_error();
					DEBUG_FPRINTF(stderr, "STSAFE> %s: PEM_write_bio_X509 failed\n", __func__);
					if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
						DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
					}
					OPENSSL_free(certRawStart);
					X509_free(x);
					BIO_free(outbio);
					StatusCode = STSAFEA_INVALID_PARAMETER;
				}
			}

			if (StatusCode == STSAFEA_OK) {
				OPENSSL_free(certRawStart);
				X509_free(x);
				BIO_free(outbio);
			}
		}

		return StatusCode;
}

static void dumpProductData(const StSafeA_ProductDataBuffer_t *const productData)
{
    if (productData == NULL) {
        CMD_FPRINTF(stderr, "ENGINE> %s: Error productData is %p\n", __func__ ,productData);
    }

#if defined(STSAFE_A110)
    CMD_FPRINTF(stdout, "STSAFE-A110 Product Information\n");
#else
    CMD_FPRINTF(stdout, "STSAFE-A100 Product Information\n");
#endif
    CMD_FPRINTF(stdout, "-------------------------------\n");

    CMD_FPRINTF(stdout, "MaskIdentification           : ");
    for (int i = 0; i < productData->MaskIdentificationLength; i++) {
        DEBUG_FPRINTF(stdout, "%02x", productData->MaskIdentification[i]);
    }
    CMD_FPRINTF(stdout, "\n");

    CMD_FPRINTF(stdout, "ST Product Number            : ");
    for (int i = 0; i < productData->STNumberLength; i++) {
        CMD_FPRINTF(stdout, "%02x", productData->STNumber[i]);
    }
    CMD_FPRINTF(stdout, "\n");

    CMD_FPRINTF(stdout, "InputOutputBufferSize        : %d\n", productData->InputOutputBufferSize);
    CMD_FPRINTF(stdout, "AtomicityBufferSize          : %d\n", productData->AtomicityBufferSize);
    CMD_FPRINTF(stdout, "NonVolatileMemorySize        : %d\n", productData->NonVolatileMemorySize);
    CMD_FPRINTF(stdout, "TestDate                     : %d\n", productData->TestDateSize);
    CMD_FPRINTF(stdout, "InternalProductVersionSize   : %d\n", productData->InternalProductVersionSize);
    CMD_FPRINTF(stdout, "ModuleDate                   : %d\n", productData->ModuleDateSize);
 #if defined(STSAFE_A110)
    CMD_FPRINTF(stdout, "FirmwareDeliveryTraceability : ");
    for (int i = 0; i < productData->FirmwareDeliveryTraceabilityLength; i++) {
        CMD_FPRINTF(stdout, "%02x", productData->FirmwareDeliveryTraceability[i]);
    }
    CMD_FPRINTF(stdout, "\n");
    CMD_FPRINTF(stdout, "BlackboxDeliveryTraceability : ");
    for (int i = 0; i < productData->BlackboxDeliveryTraceabilityLength; i++) {
        CMD_FPRINTF(stdout, "%02x", productData->BlackboxDeliveryTraceability[i]);
    }
    CMD_FPRINTF(stdout, "\n");
    CMD_FPRINTF(stdout, "PersoId                      : ");
    for (int i = 0; i < productData->PersoIdLength; i++) {
        CMD_FPRINTF(stdout, "%02x", productData->PersoId[i]);
    }
    CMD_FPRINTF(stdout, "\n");
    CMD_FPRINTF(stdout, "PersoGenerationBatchId       : ");
    for (int i = 0; i < productData->PersoGenerationBatchIdLength; i++) {
        CMD_FPRINTF(stdout, "%02x", productData->PersoGenerationBatchId[i]);
    }
    CMD_FPRINTF(stdout, "\n");
    CMD_FPRINTF(stdout, "PersoDate                    : ");
    for (int i = 0; i < productData->PersoDateLength; i++) {
        CMD_FPRINTF(stdout, "%02x", productData->PersoDate[i]);
    }
    CMD_FPRINTF(stdout, "\n");
#endif
}

/* OpenSSL Engine API demands this list be in cmd number order otherwise it'll
throw an invalid cmd number error*/
int stsafe_cmd_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    (void) e;
    (void) f;
    char *s=(char*)p;
    
    int StatusCode = 1;
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    
    if ((cmd < ENGINE_CMD_BASE) || (cmd >= STSAFE_CMD_MAX)) {
        /* if cmd < ENGINE_CMD_BASE this is being called by OpenSSL.
           In this case no work to do so just return. */
        return ENGINE_OPENSSL_SUCCESS;
    }

    DEBUG_PRINTF("stsafe_cmd_ctrl in ACTION!!! cmd = %d\n", cmd);
    
    switch (cmd) {
    case STSAFE_CMD_GET_SERIAL_NUMBER:
    {
      uint8_t *serial = stsafe_get_serial();
      if (s)
      {
        memcpy(s, serial, 9);
        return 9;
      }
      else
      {
        CMD_FPRINTF(stdout, "ST Serial Number : ");
        for (int i = 0; i < 9; i++) {
          CMD_FPRINTF(stdout, "%02x", serial[i]);
        }
        CMD_FPRINTF(stdout, "\n");
      } 
      StatusCode = 0;
      break;
    }
    case STSAFE_CMD_GET_PRODUCT_DATA:
    {
        StSafeA_ProductDataBuffer_t query_d;
        memset(&query_d, 0, sizeof(StSafeA_ProductDataBuffer_t));
        StSafeA_ProductDataBuffer_t *query = &query_d;
        StatusCode = StSafeA_ProductDataQuery(pStSafeA,
                                              query,
                                              STSAFEA_MAC_NONE);

        if ((StatusCode == 0) && (query != NULL)) {
            dumpProductData(query);
        }
        StatusCode = 0;
        break;
    }

    case STSAFE_CMD_GET_DEVICE_CERT:
    {
        CMD_FPRINTF(stdout, "ENGINE> %s: STSAFE_CMD_GET_DEVICE_CERT %s\n", __func__, (char *)p);
        if (STSAFEA_OK != readCertificate(pStSafeA, p)) {
            DEBUG_FPRINTF(stdout, "ENGINE> %s: Failed Reading Certificate %s from STSAFE\n", __func__, (char *)p);
            StatusCode  = STSAFEA_INVALID_PARAMETER;
        }
        StatusCode  = STSAFEA_OK;
        break;
    }

    case STSAFE_CMD_SET_SIG_KEY_SLOT:
    {
        CMD_FPRINTF(stdout, "ENGINE> %s: Setting STSAFE signature key slot to %ld\n", __func__, i);
        stsafe_sig_key_slot = i;
        StatusCode  = STSAFEA_OK;
        break;
    }

    case STSAFE_CMD_SET_GEN_KEY_SLOT:
    {
        CMD_FPRINTF(stdout, "ENGINE> %s: Setting STSAFE generate key slot to %ld\n", __func__, i);
        stsafe_gen_key_slot = i;
        StatusCode  = STSAFEA_OK;
        break;
    }

    case STSAFE_CMD_SET_MEMORY_REGION:
    {
        CMD_FPRINTF(stdout, "ENGINE> %s: Setting STSAFE memory region to %ld\n", __func__, i);
        stsafe_memory_region = i;
        StatusCode  = STSAFEA_OK;
        break;
    }

    case STSAFE_CMD_WRITE_DEVICE_CERT:
    {
        if (STSAFEA_OK != writeCertificate(pStSafeA, p)) {
            DEBUG_FPRINTF(stdout, "ENGINE> %s: Failed Writing Certificate %s to STSAFE\n", __func__, (char *)p);
            StatusCode  = STSAFEA_INVALID_PARAMETER;
        }
        StatusCode  = STSAFEA_OK;
        break;
    }
        
    case STSAFE_CMD_RESET:
    {
        CMD_FPRINTF(stdout, "ENGINE> %s: Reseting STSAFE hardware to default state, and then re-init the driver.\n", __func__);
        StSafeA_Reset(pStSafeA, STSAFEA_MAC_NONE);
        stsafe_init(NULL);
        StatusCode = STSAFEA_OK;
        break;
    }

    case STSAFE_CMD_HIBERNATE:
    {
        CMD_FPRINTF(stdout, "ENGINE> %s: Put the STSAFE in Hibernate state, wakeup mode %ld.\n", __func__, i);
        StatusCode = StSafeA_Hibernate(pStSafeA, i, STSAFEA_MAC_NONE);
        break;
    }
        
    case STSAFE_CMD_VERIFYPASSWORD:
    {
        CMD_FPRINTF(stdout, "ENGINE> %s: verify the password and return with status + remaining retries count within the same string.\n", __func__);
        uint8_t response[2];
        StatusCode = stsafe_password_verification((uint8_t *)p, response);
        memcpy(p, response, 2);
        break;
    }
           
    case STSAFE_CMD_ECHO:
        {
        StSafeA_LVBuffer_t echoResp;
        char               opensslerrbuff[1024];
        long int           opensslerr = 0;
        uint16_t           length = 0;

        memset(opensslerrbuff, 0x00, 1024 * sizeof(char));

        echoResp.Data = (uint8_t *) OPENSSL_malloc(STSAFEA_BUFFER_MAX_SIZE * sizeof(uint8_t));
        if(echoResp.Data == NULL)
        {
            DEBUG_FPRINTF(stderr, "STSAFE> %s: OPENSSL_malloc failed\n", __func__);
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
            }
            break;
        }
        echoResp.Length = STSAFEA_BUFFER_MAX_SIZE;
        CMD_FPRINTF(stdout, "ENGINE> %s: send the string to STSAFE A110 and send back the response from the chip.\n", __func__);

        length = strlen(p);
        if (length > (STSAFEA_BUFFER_DATA_CONTENT_SIZE - 1)) {
            CMD_FPRINTF(stdout, "ENGINE> %s: String to be sent exceeds max tranfer size, will be truncated at %d bytes\n", __func__, (STSAFEA_BUFFER_DATA_CONTENT_SIZE - 1));
            length = STSAFEA_BUFFER_DATA_CONTENT_SIZE - 1;
        }

        StatusCode = StSafeA_Echo(pStSafeA,
                                  (uint8_t *)p,
                                  length,
                                  &echoResp,
                                  STSAFEA_MAC_NONE);

        if (StatusCode == STSAFEA_OK) {
            /* we want to print string out so add null terminator */
            if (echoResp.Length < (STSAFEA_BUFFER_DATA_CONTENT_SIZE - 1)) {
                echoResp.Data[echoResp.Length] = '\0';
            } else {
                echoResp.Data[STSAFEA_BUFFER_DATA_CONTENT_SIZE - 1] = '\0';
            }

            CMD_FPRINTF(stdout, "ENGINE> %s: Echoed string len %d content is: %s\n", __func__, echoResp.Length, echoResp.Data);
        } else {
            DEBUG_FPRINTF(stderr, "ENGINE> %s: Error in echoing string from STSAFE-A110 %d\n", __func__, StatusCode);
        }
        OPENSSL_free(echoResp.Data);
            break;
    }
        
    case STSAFE_CMD_QUERY:
        /* compare string to get the query we want */
        if (p != NULL) {
            if (strcmp(QueryStr[DataPartitionQuery], p) == 0) {
                StatusCode = queryDataPartition(pStSafeA);
            }
            else if (strcmp(QueryStr[ProductDataQuery], p) == 0) {
                StatusCode = queryProductData(pStSafeA);
            }
            else if (strcmp(QueryStr[I2cParameterQuery], p) == 0) {
                StatusCode = queryI2cParameter(pStSafeA);
            }
            else if (strcmp(QueryStr[LifeCycleStateQuery], p) == 0) {
                StatusCode = queryLifeCycleState(pStSafeA);
            }
            else if (strcmp(QueryStr[HostKeySlotQuery], p) == 0) {
                StatusCode = queryHostKeySlot(pStSafeA);
            }
            else if (strcmp(QueryStr[LocalEnvelopeKeySlotQuery], p) == 0) {
                StatusCode = queryLocalEnvelopeKeySlot(pStSafeA);
            }
            else if (strcmp(QueryStr[PublicKeySlotQuery], p) == 0) {
                StatusCode = queryPublicKeySlot(pStSafeA);
            }
            else if (strcmp(QueryStr[CommandAuthorizationConfigurationQuery], p) == 0) {
                StatusCode = queryCommandAuthorizationConfiguration(pStSafeA);
            }
            else {
                StatusCode = STSAFEA_INVALID_RESP_LENGTH;
            }
        } else {
            StatusCode = STSAFEA_INVALID_RESP_LENGTH;
        }
        break;
        
        default:
            break;
    }

    if (StatusCode == STSAFEA_OK)
    {
        return ENGINE_OPENSSL_SUCCESS;
    }

    return ENGINE_OPENSSL_FAILURE;
}



