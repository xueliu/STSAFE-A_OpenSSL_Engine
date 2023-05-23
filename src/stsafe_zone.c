/**
 *********************************************************************************************
 * @file    stsafe_zone.c
 * @author  SMD application team
 * @version V1.0.1
 * @date    08-july-2020
 * @brief   Provide genreral APIs to access the Data Partition (Zone)
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "stsafea_types.h"
#include "stsafea_core.h"
#include "stsafea_conf.h"
#include "stsafea_service.h"
#include "stsafe_init.h"
#include "stsafe_api.h"

/**
  * name:   stsafe_read_zone
  *         This function read data from a data partition zone
  *
  * param   zone_index  : Specify the Zone Index .\n
  * param   offset      : Starting offset to read the data from
  *                       Range supported is from 0 up to the length of the data segment.
  * param   length      : Number of bytes to read, Must be strictly larger than 0.
  * param   data_buffer : Output Data buffer. Must be allocated by the caller.
  * retval  0 if success, 1 otherwise.
  */
int stsafe_read_zone(int zone_index, int offset, int length, unsigned char *data_buff)
{
    
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    StSafeA_LVBuffer_t Data_LV;
    int32_t StatusCode = 0;
    
    DEBUG_FPRINTF(stdout, "ENGINE> %s: Read Zone function called. \n", __func__);
    
    if((length == 0) || (data_buff == NULL))
    {
        return 1;
    }
    
    Data_LV.Data = data_buff;
    Data_LV.Length = (uint16_t)(length & 0xFFFF);
    
    StatusCode = StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, zone_index, offset, length, length, &Data_LV, STSAFEA_MAC_NONE);

    return (StatusCode == STSAFEA_OK) ? 0 : 1;
}


/**
  * name:   stsafe_update_zone
  *         This function write data to a data partition zone
  *
  * param   zone_index  : Specify the Zone Index .\n
  * param   offset      : Starting offset to write the data to
  *                       Range supported is from 0 up to the length of the data segment.
  * param   length      : Number of bytes to write, Must be strictly larger than 0.
  * param   data_buffer : Input Data buffer. Must be allocated by the caller.
  * retval  0 if success, 1 otherwise.
  */
int stsafe_update_zone(int zone_index, int offset, int length, unsigned char *data_buff)
{
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    StSafeA_LVBuffer_t Data_LV;
    int32_t StatusCode = 0;
    
    DEBUG_FPRINTF(stdout, "ENGINE> %s: Update Zone function called. \n", __func__);
    
    if((length == 0) || (data_buff == NULL))
    {
        return 1;
    }
    
    Data_LV.Data = data_buff;
    Data_LV.Length = (uint16_t)(length & 0xFFFF);

    StatusCode = StSafeA_Update(pStSafeA, 0, 0, 0, STSAFEA_AC_ALWAYS, zone_index, offset, &Data_LV, STSAFEA_MAC_NONE);
   
    return (StatusCode == STSAFEA_OK) ? 0 : 1;
}

/**
  * name:   stsafe_zone_decrement
  *         This function update a data partition zone and decrement the one-way counter
  *
  * param   zone_index    : Specify the Zone Index .\n
  * param   offset        : Starting offset to decrement the counter
  * param   amount        : Amount to be decreased to the one-way counter.
  * param   Indata_buffer : Input Data buffer. Must be allocated by the caller.
  * param   Indata_length : Input Data length.
  * param   outcounter    : Pointer to Output decrement counter. Must be allocated by the caller.
  * retval  0 if success, 1 otherwise.
  */
int stsafe_zone_decrement(int zone_index, int offset, int amount, unsigned char *indata_buffer, int indata_length, unsigned char *outcounter)
{
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    StSafeA_LVBuffer_t InData;
    StSafeA_DecrementBuffer_t OutDecrement;
    int32_t StatusCode = 0;
    
    DEBUG_FPRINTF(stdout, "ENGINE> %s: Decrement Zone counter function called. \n", __func__);
    
    if((amount == 0) || (indata_buffer == NULL) || (outcounter == NULL))
    {
        return 1;
    }
    
    InData.Data = indata_buffer;
    InData.Length = (uint16_t)(indata_length & 0xFFFF);
    
    StatusCode = StSafeA_Decrement(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, zone_index, offset, amount, &InData, &OutDecrement, STSAFEA_MAC_NONE);

    *outcounter = OutDecrement.OneWayCounter;
    
    return (StatusCode == STSAFEA_OK) ? 0 : 1;
}


#define MAX_READ_UPDATE_CONTENT (STSAFEA_BUFFER_DATA_CONTENT_SIZE - 4)

int32_t stsafe_read_certificate(uint8_t zone, uint8_t **buffer, size_t *size)
{
	StSafeA_Handle_t *pStSafeA = &stsafea_handle;
	StSafeA_LVBuffer_t stsRead;
	char     opensslerrbuff[1024];

	long int  opensslerr      = 0;
	uint16_t  certificateSize = 0;
	uint8_t  *certRawStart    = NULL;
	uint8_t  *certRawCurr     = NULL;
	int32_t   StatusCode      = STSAFEA_OK;
	uint32_t  numBytesRead    = 0;
	uint32_t  offsetBytes     = 0;
	uint32_t  numReads        = 0;
	uint32_t  finalBytes      = 0;

	if (buffer == NULL || size == NULL)
		return STSAFEA_INVALID_PARAMETER;
	*buffer = NULL;
	*size = 0;
	memset(opensslerrbuff, 0x00, 1024 * sizeof(char));
	memset(&stsRead, 0x00, sizeof(StSafeA_LVBuffer_t));
	DEBUG_FPRINTF(stdout, "STSAFE> %s: OPENSSL_malloc size is %zd bytes\n", __func__, MAX_READ_UPDATE_CONTENT * sizeof(uint8_t));
	stsRead.Data = OPENSSL_malloc(MAX_READ_UPDATE_CONTENT);
  stsRead.Length = MAX_READ_UPDATE_CONTENT;
	if(stsRead.Data == NULL) {
		opensslerr = ERR_get_error();
		DEBUG_FPRINTF(stderr, "STSAFE> %s: OPENSSL_malloc failed\n", __func__);
		if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
			DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
		}
		StatusCode = STSAFEA_INVALID_PARAMETER;
	}

	if (StatusCode == STSAFEA_OK) {
		stsRead.Length = STSAFEA_BUFFER_MAX_SIZE;

		StatusCode = StSafeA_Read(pStSafeA,
				0,
				0,
				STSAFEA_AC_ALWAYS,
				zone,
				0,
				4,
				4,
				&stsRead,
				STSAFEA_MAC_NONE);

		if ((StatusCode == 0) && (stsRead.Data != NULL)) {
			switch (stsRead.Data[1])
			{
				case 0x81:
					certificateSize = stsRead.Data[2] + 3;
					break;

				case 0x82:
					certificateSize = (((uint16_t)stsRead.Data[2]) << 8) + stsRead.Data[3] + 4;
					break;

				default:
					if (stsRead.Data[1] < 0x81){
						certificateSize = stsRead.Data[1];
					}
					break;
			}
		}
	}

	if (StatusCode == STSAFEA_OK) {
		/* allocate memory for whole certificate */
		certRawStart = OPENSSL_malloc(certificateSize * sizeof(uint8_t));
		if (certRawStart == NULL) {
			opensslerr = ERR_get_error();
			DEBUG_FPRINTF(stderr, "STSAFE> %s: OPENSSL_malloc failed\n", __func__);
			if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
				DEBUG_FPRINTF(stderr, "STSAFE> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
			}
			StatusCode = STSAFEA_INVALID_PARAMETER;
		}
	}

	if (StatusCode == STSAFEA_OK) {
		/* calculate number of I2C read needed */

		numReads   = certificateSize/MAX_READ_UPDATE_CONTENT;
		finalBytes = certificateSize - (numReads * MAX_READ_UPDATE_CONTENT);
		if (finalBytes) {
			numReads++;
		}
		numBytesRead = MAX_READ_UPDATE_CONTENT;
		certRawCurr  = certRawStart;

		DEBUG_FPRINTF(stdout, "STSAFE> %s: certificateSize %d numWrites %d finalBytes %d\n",
				__func__, certificateSize, numReads, finalBytes);

		for (uint32_t readNum = 0; readNum < numReads; readNum++) {
			if ( (readNum + 1) == numReads) {
				numBytesRead = finalBytes;
			}

			StatusCode = StSafeA_Read(pStSafeA,
					0,
					0,
					STSAFEA_AC_ALWAYS,
					zone,
					offsetBytes,
					numBytesRead,
					numBytesRead,
					&stsRead,
					STSAFEA_MAC_NONE);

			if (StatusCode == STSAFEA_OK) {
				DEBUG_FPRINTF(stdout, "STSAFE> %s: Read number %02d numBytesRead: %d\n",
						__func__, readNum, numBytesRead);
				DEBUG_FPRINTF(stdout, "STSAFE> %s: Chunk data                 : ", __func__);
				for(uint32_t i = 0; i < numBytesRead; i++) {
					DEBUG_FPRINTF(stdout, "%02x",stsRead.Data[i]);
				}
				DEBUG_FPRINTF(stdout, "\n");

				/* data to temp store */
				DEBUG_FPRINTF(stdout, "Copying %d bytes to %p\n", numBytesRead, certRawCurr);
				memcpy(certRawCurr, stsRead.Data, numBytesRead);
				certRawCurr = certRawCurr + numBytesRead;
				offsetBytes = offsetBytes + numBytesRead;
			} else {
				readNum   = numReads;
				OPENSSL_free(certRawStart);
				StatusCode = STSAFEA_INVALID_PARAMETER;
			}
		}
		if (StatusCode == STSAFEA_OK)
		{
			*buffer = certRawStart;
			*size = certificateSize;
		}
	}

	if (stsRead.Data != NULL)
		OPENSSL_free(stsRead.Data);
	return StatusCode;
}


