/**
 *********************************************************************************************
 * @file    test_stsafe_engine.c
 * @author  SMD application team
 * @version V1.0.0
 * @date    22-July-2020
 * @brief   Openssl STSAFE Engine test 
 *********************************************************************************************
 * @attention
 *
 * <h2><center>&copy; COPYRIGHT 2020 STMicroelectronics</center></h2>
 *
 * Licensed under ST MYLIBERTY SOFTWARE LICENSE AGREEMENT (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *        http://www.st.com/myliberty
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied,
 * AND SPECIFICALLY DISCLAIMING THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *********************************************************************************************
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>

#include <stsafe_init.h>
#include <stsafe_api.h>
#include "test_stsafe_engine.h"

#define OPENSSL_LOAD_CONF	1
#define STSAFE_ECDSA_TEST 1
int debug_level=0;
/*
 * Sizes for envelope wrap and unwrap
 */
#define ENVELOPE_SIZE       (8*60)              /* non-zero multiple of 8 bytes; max 480(=8*60) */
#define WRAP_RESPONSE_SIZE  (ENVELOPE_SIZE + 8) /* Local Envelope response data is 8-bytes longer than the working key (see User Manual). */

/*
 * Memory region test zone
 */
#define MEMORY_REGION_TEST_ZONE 3

#define STS_CHK(ret, f)                     if ((ret) == 0) { ret = f; }

ENGINE *stsafe_engine = NULL;

static void     GenerateTestHeader(char *testTitle);
static void     GenerateTestPassFooterWithStr(char *testTitle);
static void     GenerateTestFailFooter(void);

extern uint32_t GenerateUnsignedChallenge(size_t size, uint8_t* buf)
{
    uint32_t StatusCode = 0;

    if (buf != NULL) {
        struct timespec one_time;
        uint16_t i = 0;

        clock_gettime(CLOCK_REALTIME, &one_time);

        srand(one_time.tv_nsec);

        for (i = 0; i < size; i++)
        {
            buf[i] = rand() % 256;
        }

        buf[0] &= 0x7F;
    } else {
        printf("%s> Error buf %p\n", __func__, buf);
        StatusCode = -1;
    }

    return (StatusCode);
}

static void GenerateTestHeader(char *testTitle)
{
    printf("==============================================================\n");
    printf("===== %-50s =====\n", testTitle);
    printf("==============================================================\n");
}

static void GenerateTestPassFooterWithStr(char *testTitle)
{
    printf("==============================================================\n");
    printf("===== PASS %-45s =====\n", testTitle);
    printf("==============================================================\n\n");
}

static void GenerateTestFailFooter(void)
{
    printf("==============================================================\n");
    printf("===== %-50s =====\n", "FAIL");
    printf("==============================================================\n\n");
}

static void GenerateTestFailFooterWithStr(char *testTitle)
{
    printf("==============================================================\n");
    printf("===== FAIL %-45s =====\n", testTitle);
    printf("==============================================================\n\n");
}

static void STS_PRT(const char *title, unsigned char *buf, int length)
{
    int i = 0, j = 0;
    printf("%s: \n      ", title);
    for(i = 0; i < length; i++)
    {
        printf("%02x ", buf[i]);
        if(++j >= 16) { printf("\n      "); j = 0; }
    }
    printf("\n");
}


int main(int ac, char **argv)
{
    char     opensslerrbuff[1024];
    long int opensslerr = 0;
    int32_t  result     = 0;
    time_t   t;

    OPENSSL_INIT_SETTINGS *settings = NULL;
    time(&t);
		if (ac >= 2)
			debug_level = atoi(argv[1]);

    printf("STSAFE OpenSSL Engine Test Suite\n");
    printf("--------------------------------\n");
    printf("\n");
    printf("Run Date: %s\n", ctime(&t));

    GenerateTestHeader("Pre Test Configuration");

    /* An Application can call this function - but if the library is unloaded 
        and cleaned up the config file won't be reloaded since this function 
        is only allowed to run once */
    settings = OPENSSL_INIT_new();
    if (settings == NULL) {
        GenerateTestFailFooterWithStr("Pre Test Configuration");
        result = -1;
    }

    if (result == 0) {
        if (0 == OPENSSL_INIT_set_config_appname(settings,"./openssl.conf.stsafe")) {
            GenerateTestFailFooterWithStr("Pre Test Configuration");
            result = -1;
        }
    }

    if (result == 0) {
        if (0 == OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, settings)) {
            GenerateTestFailFooterWithStr("Pre Test Configuration");
            result = -1;
        }
    }
    if (result == 0) {
        GenerateTestPassFooterWithStr("Pre Test Configuration");
        
        GenerateTestHeader("Test 1 STSAFE Load Engine");

        /* Load the engine for testing */
        stsafe_engine = ENGINE_by_id("Stsafe");
        if (stsafe_engine == NULL) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from ENGINE_by_id\n");
            printf("=====================================\n");
            result = -1;
        }
    }

    if (result == 0) {
        GenerateTestPassFooterWithStr("Test 1 STSAFE Load Engine");

        GenerateTestHeader("Test 2 STSAFE Engine Init");

        /* structural reference to the STSAFE ENGINE*/
        if (! ENGINE_init(stsafe_engine)) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from ENGINE_init\n");
            printf("=====================================\n");
            ENGINE_free(stsafe_engine);
            result = -1;
        }
    }
    if (result == 0) {
        GenerateTestPassFooterWithStr("Test 2 STSAFE Engine Init");

        GenerateTestHeader("Test 3 STSAFE Get product Data");

        /*Get the STSAFE Product data using Engine Ctrl function*/
        if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_GET_PRODUCT_DATA, 0 , NULL, 0)) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s", opensslerr, opensslerrbuff);
            }
            printf("===== FAIL - Error from ENGINE_ctrl\n");
            printf("==========================================\n");
            ENGINE_free(stsafe_engine);
            result = -1;
        }
    }

    if (result == 0) {
        GenerateTestPassFooterWithStr("Test 3 STSAFE Get product Data");

        GenerateTestHeader("Test 4 STSAFE Wrap Data");

        unsigned char envelopeIn[ENVELOPE_SIZE]           = { 0 };
        unsigned char envelopeUnWrapOut[ENVELOPE_SIZE]    = { 0 };
        unsigned char envelopeWrapOut[WRAP_RESPONSE_SIZE] = { 0 };

        /* generate full amount of data */
        printf("===== Generate %d bytes of data to wrap\n", ENVELOPE_SIZE);
        if (GenerateUnsignedChallenge(ENVELOPE_SIZE, envelopeIn) != 0) {
            printf("===== Error generate %d bytes of data to wrap\n", ENVELOPE_SIZE);
            result = -1;
            GenerateTestFailFooterWithStr("Test 4 STSAFE Wrap Data");
        }

        if (result == 0) {
            /* wrap data */
            if (stsafe_AES_wrap_key(0, envelopeWrapOut, envelopeIn, ENVELOPE_SIZE) != 0) {
                GenerateTestFailFooterWithStr("Test 4 STSAFE Wrap Data");
                result = -1;
            }
        }

        if (result == 0) {
            printf("envelopeIn\n");
            printf("0x");
            for (uint32_t i = 0; i < ENVELOPE_SIZE; i++) {
                if ( (i != 0) && ((i % 8) == 0) ) {
                    printf("\n");
                    printf("0x");
                }
                printf("%02x", envelopeIn[i]);
            }
            printf("\n");

            GenerateTestPassFooterWithStr("Test 4 STSAFE Wrap Data");

            GenerateTestHeader("Test 5 STSAFE Unwrap Data");

            /* now unwrap and compare with origioanl message */
            if (stsafe_AES_unwrap_key(0, envelopeUnWrapOut, envelopeWrapOut, WRAP_RESPONSE_SIZE) != 0) {
                GenerateTestFailFooter();
                result = -1;
            }
            if (result == 0) {
                if (memcmp(envelopeIn, envelopeUnWrapOut, ENVELOPE_SIZE) != 0) {
                    printf("envelopeIn          envelopeUnWrapOut\n");
                    for (uint32_t i = 0; i < ENVELOPE_SIZE; i = i + 8) {
                        printf("0x%02x%02x%02x%02x%02x%02x%02x%02x  0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                               envelopeIn[i + 0], envelopeIn[i + 1], envelopeIn[i + 2], envelopeIn[i + 3],
                               envelopeIn[i + 4], envelopeIn[i + 5], envelopeIn[i + 6], envelopeIn[i + 7],
                               envelopeUnWrapOut[i + 0], envelopeUnWrapOut[i + 1],
                               envelopeUnWrapOut[i + 2], envelopeUnWrapOut[i + 3],
                               envelopeUnWrapOut[i + 4], envelopeUnWrapOut[i + 5],
                               envelopeUnWrapOut[i + 6], envelopeUnWrapOut[i + 7]);
                    }
                    printf("\n");

                    GenerateTestFailFooter();
                    result = -1;
                }
            }
        }
    }

    if (result == 0) {
        GenerateTestPassFooterWithStr("Test 5 STSAFE Unwrap Data");

        GenerateTestHeader("Test 6 STSAFE ECDSA Sign/Verify");

        result = ecdsa_test();

        if (result == 0){
            GenerateTestPassFooterWithStr("Test 6 STSAFE ECDSA Sign/Verify");
        } else {
            GenerateTestFailFooterWithStr("Test 6 STSAFE ECDSA Sign/Verify");
        }
    }

    if (result == 0) {
        GenerateTestHeader("Test 7 STSAFE ECDH/Generate Ephemeral Keys");

        result = ecdh_test();

        if (result == 0) {
            GenerateTestPassFooterWithStr("Test 7 STSAFE ECDH/Generate Ephemeral Keys");
        } else {
            GenerateTestFailFooterWithStr("Test 7 STSAFE ECDH/Generate Ephemeral Keys");
        }
    }

    if (result == 0) {
        GenerateTestHeader("Test 8 STSAFE Private Key Methods");

        result = pkey_test();

        if (result == 0) {
            GenerateTestPassFooterWithStr("Test 8 STSAFE Private Key Methods");
        } else {
            GenerateTestFailFooterWithStr("Test 8 STSAFE Private Key Methods");
        }
    }

    if (result == 0) {
        GenerateTestHeader("Test 9 STSAFE Randon Number Generation");

        result = rand_test();

        if (result == 0) {
            GenerateTestPassFooterWithStr("Test 9 STSAFE Randon Number Generation");
        } else {
            GenerateTestFailFooterWithStr("Test 9 STSAFE Randon Number Generation");
        }
    }

    if (result == 0) {
      GenerateTestHeader("Test 10 STSAFE Zone Data Read/update Test");

      unsigned char Data[1024];

      Data[0] = 0xBE; Data[1] = 0xEF;
      for(int i=2; i<1024; i++)
      {
          Data[i]= i & 0xff;
      }

      /* Zone Update */
      STS_CHK(result, stsafe_update_zone(MEMORY_REGION_TEST_ZONE, 0, 100, Data));
      if(!result)STS_PRT("READ test : Updated data 100 bytes to Zone 0x6", Data, 100);
      
      STS_CHK(result, stsafe_update_zone(MEMORY_REGION_TEST_ZONE, 0, 499, Data));
      if(!result)STS_PRT("READ test : Updated data 499 bytes to Zone 0x6", Data, 499);


      /* Zone Read */
      STS_CHK(result, stsafe_read_zone(MEMORY_REGION_TEST_ZONE, 0, 100, Data));
      if(!result)STS_PRT("READ test : Reading data 100 bytes from Zone 0x6", Data, 100);

      STS_CHK(result, stsafe_read_zone(MEMORY_REGION_TEST_ZONE, 0, 499, Data));
      if(!result)STS_PRT("READ test : Reading data 499 bytes from Zone 0x6", Data, 499);
      
      /* Zone Decrement */
      unsigned char outcounter = 0;
      STS_CHK(result, stsafe_zone_decrement(6, 0, 1, Data, 1, &outcounter));
      if(!result)printf("READ test : Decrement Zone index 6 counter by 1, now it is: %d\n", outcounter);
      
    }

    if (result == 0) {
        GenerateTestPassFooterWithStr("Test 10 STSAFE Zone Data Read/update Test");
  
        GenerateTestHeader("Test 11 STSAFE Query Test");

        result = query_test();

        if (result == 0)
            GenerateTestPassFooterWithStr("Test 11 STSAFE Query Test");
        else
            GenerateTestFailFooterWithStr("Test 11 STSAFE Query Test");
    }

    if (result == 0) {
        GenerateTestHeader("Test 12 STSAFE ECHO Test");
        
/*
 *   STSAFE_CMD_ECHO              |      e     | STSAFE_CMD_ECHO              |      0          | Input string to echo       |     NULL         |
 */
        const char echostring[] = "Pinging STSafe";
        uint8_t echo[507] = {0};
        memset(echo, 0, 507);
        memcpy(echo, echostring, sizeof(echostring));

        if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_ECHO, 0 , echo, 0)) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("==========================================\n");
            printf("===== FAIL - Error from ENGINE_ctrl\n");
            printf("==========================================\n");
            ENGINE_free(stsafe_engine);
            result = -1;
        }
        else
        {
            printf("ECHO CMD returns %s. Originally sent %s\n", echo, echostring);
            result = 0;
        }
  }
  
    if (result == 0) {
        GenerateTestPassFooterWithStr("Test 12 STSAFE ECHO Test");

      /*
       * Some STSAFE-A110 cards do not have the correct profile setup that enables the password function
       * test to be run.
       */
        GenerateTestHeader("Test 13 Verify Password Test");

/*
 *   STSAFE_CMD_VERIFYPASSWORD    |      e     | STSAFE_CMD_VERIFYPASSWORD    |      0          | Input/Output byte string   |     NULL         |
 */
        
        const char passstring[] = "Banana101";
        uint8_t pp[16] = {0};
        memset(pp, 0, 16);
        memcpy(pp, passstring, sizeof(passstring));
        
        if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_VERIFYPASSWORD, 0 , pp, 0)) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("==========================================\n");
            printf("===== FAIL - Error from ENGINE_ctrl\n");
            printf("==========================================\n");
            ENGINE_free(stsafe_engine);
            result = -1;
        }
        else
        {
            printf("Verify Password CMD returns status 0x%02x. Retry count = %d, Originally sent password %s\n", pp[0], pp[1], passstring);
            result = 0;
        }
       
  }

    if (result == 0) {
        GenerateTestPassFooterWithStr("Test 13 Verify Password Test");

        GenerateTestHeader("Test 14 Reset Test");

/*
 *   STSAFE_CMD_RESET             |      e     | STSAFE_CMD_RESET             |      0          |      NULL                  |     NULL         |
 */
        if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_RESET, 0 , 0, 0)) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("==========================================\n");
            printf("===== FAIL - Error from ENGINE_ctrl\n");
            printf("==========================================\n");
            ENGINE_free(stsafe_engine);
            result = -1;
        }
        else
        {
            result = 0;
        }

  }

    if (result == 0) {
        GenerateTestPassFooterWithStr("Test 14 Reset Test");
  
        GenerateTestHeader("Test 15 Hibernate Test");

/*
 *   STSAFE_CMD_HIBERNATE         |      e     | STSAFE_CMD_HIBERNATE         | Wakeup code     |      NULL                  |     NULL         |
 * #define STSAFEA_WAKEUP_FROM_I2C_START_OR_RESET          (( uint8_t ) 0x01 )
 * #define STSAFEA_WAKEUP_FROM_RESET                       (( uint8_t ) 0x02 )
 */
        if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_HIBERNATE, 1 , 0, 0)) {
            opensslerr = ERR_get_error();
            if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
                printf("===== OpenSSL error %ld %s\n", opensslerr, opensslerrbuff);
            }
            printf("==========================================\n");
            printf("===== FAIL - Error from ENGINE_ctrl\n");
            printf("==========================================\n");
            ENGINE_free(stsafe_engine);
            result = -1;
        }
        else
        {
            result = 0;
        }
  }

    if (result == 0) {
        GenerateTestPassFooterWithStr("Test 15 Hibernate Test");
    }
    
    printf("==============================================================\n");
    printf("===== %-50s =====\n", "END OF TEST!!!!");
    printf("==============================================================\n\n");

   /* Release the functional reference from ENGINE_init() */
    ENGINE_finish(stsafe_engine);
   /* Release the structural reference from ENGINE_by_id() */
    ENGINE_free(stsafe_engine);
    
}

void StSafeA_Delay(uint32_t Delay)
{
    usleep(Delay*1000);
}

