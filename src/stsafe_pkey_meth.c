/**
 *********************************************************************************************
 * @file    stsafe_pkey_meth.c
 * @author  SMD application team
 * @version V1.0.1
 * @date    08-july-2020
 * @brief   Openssl STSAFE Engine Pkey methods 
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
#include <openssl/evp.h>
#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/sha.h"
#include "openssl/pem.h"
#include "openssl/opensslv.h"
#include "openssl/x509.h"

#include "stsafe_api.h"
#include "stsafe_init.h"

#include "stsafea_types.h"
#include "stsafea_core.h"
#include "stsafea_conf.h"
#include "stsafea_crypto.h"
#include "stsafea_service.h"

static struct _stsane_pkey_def_f {
    int(*init) (EVP_PKEY_CTX *ctx);
    int(*paramgen_init) (EVP_PKEY_CTX *ctx);
    int(*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int(*keygen_init) (EVP_PKEY_CTX *ctx);
    int(*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int(*sign_init) (EVP_PKEY_CTX *ctx);
    int(*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen);
    int(*derive_init) (EVP_PKEY_CTX *ctx);
    int(*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
} stsafe_pkey_def_f;


static EVP_PKEY_METHOD * stsafe_pkey_meth = NULL;

static int stsafe_pkey_meth_ids[] = { EVP_PKEY_EC, 0 };

/** \brief Check if the eckey provided is one that matches the keys created by/for
the engine */
int stsafe_eckey_is_stsafe_key(EC_KEY * ec)
{
    int ret = ENGINE_OPENSSL_FAILURE;

    DEBUG_PRINTF_API("%s: ec key %p\n", __func__, ec);
    stsafe_ecc_ex_data_t *data;

    data = stsafe_ecc_getappdata(ec);

    if (data == NULL)
    {
      /* not a STSAFE-A110 key */
      return ret;
    }
    
    if(memcmp(stsafe_get_serial(), data->serial, 9) != 0)
    {
      return ret;
    }
    ret = ENGINE_OPENSSL_SUCCESS;

    return ret;
}


/** \brief Check if the pkey provided is one that has been created by/for 
the engine */
int stsafe_pkey_is_stsafe_key(EVP_PKEY * pkey)
{
    int ret = ENGINE_OPENSSL_FAILURE;
    EC_KEY * ec_key = NULL;

    DEBUG_PRINTF_API("stsafe_pkey_is_stsafe_key called %p %d - %d\n", pkey, ret, ENGINE_OPENSSL_SUCCESS);
    if (pkey)
    {
        ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        if (ec_key)
        {
            ret = stsafe_eckey_is_stsafe_key(ec_key); 
            EC_KEY_free(ec_key);
        }
    }
    DEBUG_PRINTF_API("stsafe_pkey_is_stsafe_key return =%d %p\n",ret, ec_key);
    return ret;
}


/**
 *
 * \brief Allocates the EVP_PKEY structure and load the ECC
 *        public key returned by the stsafe chip
 *
 * \param[in] e - a pointer to the engine (stsafe in our case).
 * \param[in] pkey - a pointer to EVP_PKEY
 * \param[in] key_id - a string for key ID (not used by the atstsafe engine)
 * \return EVP_PKEY for success, NULL otherwise
 */
static EVP_PKEY* stsafe_load_pubkey_internal(ENGINE *e, EVP_PKEY * pkey, const char* key_id)
{
	(void)key_id;

	DEBUG_PRINTF_API("STSAFE_PKEY> %s called\n", __func__);

	if(!pkey)
	{
		pkey = stsafe_key_read(key_id);

		if (pkey)
		{
			DEBUG_PRINTF_API("STSAFE_PKEY> %s pkey = %p, ec_key = %p\n", __func__, pkey, EVP_PKEY_get1_EC_KEY(pkey));

			/* Update the reference counter */
			if(!ENGINE_init(e))
			{
				DEBUG_PRINTF_API("STSAFE_PKEY> %s Public key load:  Engine init failed\n", __func__);
				return NULL;
			}

			DEBUG_PRINTF_API("STSAFE_PKEY> %s: new PKEY created %p\n", __func__, pkey);

			EVP_PKEY_set1_engine(pkey,e);
		}
		else
		{
			StSafeA_Handle_t *pStSafeA = &stsafea_handle;
			size_t CertificateSize = 0;
			int32_t  StatusCode      = 0;
			uint8_t *CertData = NULL;
			StatusCode = stsafe_read_certificate(stsafe_memory_region, &CertData, & CertificateSize);

			/* Update the reference counter */
			if(!ENGINE_init(e))
			{
				DEBUG_PRINTF_API("STSAFE_PKEY> %s Public key load:  Engine init failed\n", __func__);
				return NULL;
			}

			/* Parse STSAFE-A's X509 CRT certificate */
			if ((StatusCode == 0) && (CertData != NULL))
			{
				pkey = EVP_PKEY_new();

				DEBUG_PRINTF_API("STSAFE_PKEY> %s StSafeA_Read Success CertificateSize = %d\n", __func__, CertificateSize);
				const unsigned char *CertificatePos = CertData;
				X509 *Cert = d2i_X509(NULL, &CertificatePos, CertificateSize);

				OPENSSL_free(CertData);
				/* Get Certificate public key */
				if (Cert != NULL)
				{
				    EVP_PKEY *CertPublicKey = X509_get_pubkey(Cert);
				    X509_free(Cert);
				    EC_KEY* eckey_pub;
				    eckey_pub = EVP_PKEY_get1_EC_KEY(CertPublicKey);
				    OPENSSL_free(CertPublicKey);
				    EVP_PKEY_set1_EC_KEY(pkey,EC_KEY_dup(eckey_pub));
				    EC_KEY_free(eckey_pub);
				    stsafe_ecc_ex_data_t *data;

				    data = OPENSSL_malloc(sizeof(*data));

				    data->slot=0;
				    memcpy(data->serial, stsafe_get_serial(), 9);
				    data->magic = STSAFE_ECC_APP_DATA_MAGIC;
				    stsafe_ecc_setappdata(EVP_PKEY_get0_EC_KEY(pkey), data);
				    EVP_PKEY_set1_engine(pkey,e);
				}
			}
		}
		DEBUG_PRINTF_API("STSAFE_PKEY> %s returns pkey %p\n", __func__, pkey);
		return pkey;
	}
	else
	{
		DEBUG_PRINTF_API("STSAFE_PKEY> %s pkey NOT NULL.\n", __func__);
	}

	DEBUG_PRINTF_API("STSAFE_PKEY> %s returns pkey\n", __func__);
	return pkey;

}

int stsafe_ssl_client_cert(ENGINE *e, SSL *ssl, STACK_OF(X509_NAME) *ca_dn, X509 **pcert, EVP_PKEY **pkey, STACK_OF(X509) **pother, UI_METHOD *ui_method, void *callback_data)
{
    (void)ui_method;
    (void)callback_data;
    (void)pother;
    (void)ssl;
    (void)ca_dn;

    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    size_t CertificateSize = 0;
    int32_t  StatusCode      = 0;
    uint8_t *CertData = NULL;

    DEBUG_PRINTF_API("STSAFE_PKEY> %s called\n", __func__);
    *pkey = stsafe_load_pubkey_internal(e, NULL, NULL);
    if (*pkey)
    {
      DEBUG_PRINTF_API("STSAFE_PKEY> %s returns 0\n", __func__);
      /* Extract STSAFE-A's X509 CRT certificate */
      StatusCode = stsafe_read_certificate(stsafe_memory_region, &CertData, &CertificateSize);

      /* Parse STSAFE-A's X509 CRT certificate */
      if ((StatusCode == 0) && (CertData != NULL))
      {
        DEBUG_PRINTF_API("STSAFE_PKEY> %s StSafeA_Read Success CertificateSize = %d\n", __func__, CertificateSize);
        const unsigned char *CertificatePos = CertData;
        *pcert = d2i_X509/*_AUX*/(NULL, &CertificatePos, CertificateSize);
	OPENSSL_free(CertData);
      }
      return 0;
    }
    DEBUG_PRINTF_API("STSAFE_PKEY> %s returns 1\n", __func__);
    return 1;
}


/** \brief Allocate an EVP_PKEY structure and initialize it
This is through the public key API */
EVP_PKEY* stsafe_load_pubkey(ENGINE *e, const char *key_id,
                             UI_METHOD *ui_method, void *callback_data)
{
    (void)ui_method;
    (void)callback_data;
    DEBUG_PRINTF_API("STSAFE_PKEY> %s called\n", __func__);
    return stsafe_load_pubkey_internal(e, NULL, key_id);
}


/** \brief Allocate an EVP_PKEY structure and initialize it
    This is through the private key API */
EVP_PKEY* stsafe_load_privkey(ENGINE *e, const char *key_id, 
                              UI_METHOD *ui_method, void *callback_data)
{
    (void)ui_method;
    (void)callback_data;
    DEBUG_PRINTF_API("stsafe_load_privkey called \n");
    return stsafe_load_pubkey_internal(e, NULL, key_id);
}

#ifndef STSAFE_DEFAULT_KEY
#define STSAFE_DEFAULT_KEY 1
#endif

/** \brief Intercept key initialization and see if the incoming context is a
saved key specific for this device */
int stsafe_pkey_ec_init(EVP_PKEY_CTX *ctx)
{
  DEBUG_PRINTF_API("stsafe_pkey_ec_init called EVP_PKEY_CTX = %p\n", ctx);
  if (ctx)
  {    
    DEBUG_PRINTF_API("stsafe_pkey_ec_init ctx not NULL %p\n", EVP_PKEY_CTX_get0_pkey(ctx));
    /* Check if the key is actually meta data pertaining to an stsafe 
       device configuration */
    if (stsafe_pkey_is_stsafe_key(EVP_PKEY_CTX_get0_pkey(ctx)))
    {
      /* Load the public key from the device - OpenSSL would have already
         checked the key against a cert if it was asked to use the cert so
         this may be redundant depending on the use */
      if (!stsafe_load_pubkey_internal(EVP_PKEY_get0_engine(EVP_PKEY_CTX_get0_pkey(ctx)), 
            EVP_PKEY_CTX_get0_pkey(ctx), NULL))
      {
        DEBUG_PRINTF_API("stsafe_pkey_ec_init return ENGINE_OPENSSL_FAILURE \n");
        return ENGINE_OPENSSL_FAILURE;
      }
    }
    else
    {
      if (EVP_PKEY_CTX_get0_pkey(ctx))
      {
        /* external key usage */
        /* set default to STSAFE_DEFAULT_KEY */
        stsafe_ecc_ex_data_t *data;

        data = OPENSSL_malloc(sizeof(*data));

        data->slot=STSAFE_DEFAULT_KEY;
        memcpy(data->serial, stsafe_get_serial(), 9);
        data->magic = STSAFE_ECC_APP_DATA_MAGIC;
        stsafe_ecc_setappdata(EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx)), data);
        DEBUG_PRINTF_API("%s: adding STSAFE slot %ld to external key\n", __func__, data->slot);	
      }
    }
  }

  DEBUG_PRINTF_API("stsafe_pkey_ec_init returned\n");
  return stsafe_pkey_def_f.init ? stsafe_pkey_def_f.init(ctx)
    : ENGINE_OPENSSL_SUCCESS;
}


static int stsafe_pkey_ec_sign_init(EVP_PKEY_CTX *ctx)
{

    DEBUG_PRINTF_API("stsafe_pkey_ec_sign_init called\n");
    return stsafe_pkey_def_f.sign_init ? stsafe_pkey_def_f.sign_init(ctx)
        : ENGINE_OPENSSL_SUCCESS;
}


static int stsafe_pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, 
                               size_t *siglen, const unsigned char *tbs, size_t tbslen)
{

    DEBUG_PRINTF_API("stsafe_pkey_ec_sign called \n");
    if (stsafe_pkey_is_stsafe_key(EVP_PKEY_CTX_get0_pkey(ctx)))
    {
        DEBUG_PRINTF_API("stsafe_pkey_ec_sign ---1\n");
        int ret = ENGINE_OPENSSL_FAILURE;
        EC_KEY * ec = EVP_PKEY_get1_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));
        ECDSA_SIG *ecs = NULL;

        do
        {
        
            DEBUG_PRINTF_API("stsafe_pkey_ec_sign ---signlen=%zd\n",*siglen);
            if (siglen)
            {
                /* Return required signature length */
                if (!sig) {
                    *siglen = ECDSA_size(ec);
                    ret = ENGINE_OPENSSL_SUCCESS;
                    break;
                }
                else if (*siglen < (size_t)ECDSA_size(ec)) {
                    ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
                    break;
                }
            }
            else
            {
                /* Invalid call method */
                break;
            }
            DEBUG_PRINTF_API("stsafe_pkey_ec_sign ---tbslen=%zd\n",tbslen);
            ecs = stsafe_engine_ecdsa_do_sign(tbs, tbslen, NULL, NULL, ec);

            *siglen = ecs ? i2d_ECDSA_SIG(ecs, &sig): 0;

            ret = ENGINE_OPENSSL_SUCCESS;
        } while (0);

        
        DEBUG_PRINTF_API("stsafe_pkey_ec_sign ---signlen=%ld\n",*siglen);

        if (ecs)
        {
            ECDSA_SIG_free(ecs);
        }

        if (ec)
        {
            EC_KEY_free(ec);
        }

        return ret;
    }
    else
    {
        return stsafe_pkey_def_f.sign ?
            stsafe_pkey_def_f.sign(ctx, sig, siglen, tbs, tbslen)
            : ENGINE_OPENSSL_SUCCESS;
    }
}

/**
 *
 * \brief Initialize the EVP_PKEY_METHOD method callback for
 *        stsafe engine. Just returns a pointer to
 *        EVP_PKEY_METHOD stsafe_pkey_meth
 *
 * \param[in] e - a pointer to the engine (atstsafe in our case).
 * \param[out] pkey_meth - a double pointer to EVP_PKEY_METHOD
 *       to return the EVP_PKEY_METHOD stsafe_pkey_meth
 * \param[out] nids - a double pointer to return an array of nid's (we return 0)
 * \param[in] nid - a number of expected nid's (we ignore this parameter)
 * \return 1 for success
 */
int stsafe_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pkey_meth,
                       const int **nids, int nid)
{
    (void)e;
    DEBUG_PRINTF_API("stsafe_pkey_meths called nid=%d\n",nid);
    if (!pkey_meth) {
        *nids = stsafe_pkey_meth_ids;
        return 1;
    }

    if (EVP_PKEY_EC == nid)
    {
        *pkey_meth = stsafe_pkey_meth;
        return ENGINE_OPENSSL_SUCCESS;
    }
    else
    {
        *pkey_meth = NULL;
        return ENGINE_OPENSSL_FAILURE;
    }
}

/**
 *
 * \brief Allocate and initialize a pkey method structure for the engine
  * \return 1 for success
 */
int stsafe_pkey_meth_init(void)
{
    const EVP_PKEY_METHOD * defaults;
    DEBUG_PRINTF_API("stsafe_pkey_meth_init called\n");
    if (!stsafe_pkey_meth)
    {
        stsafe_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
    }
    
    if (!stsafe_pkey_meth)
    {
        return ENGINE_OPENSSL_FAILURE;
    }

    defaults = EVP_PKEY_meth_find(EVP_PKEY_EC);

    /* Copy the default methods */
    EVP_PKEY_meth_copy(stsafe_pkey_meth, defaults);

    /* Retain default methods we'll be replacing */
    EVP_PKEY_meth_get_init(defaults, &stsafe_pkey_def_f.init);
    EVP_PKEY_meth_get_sign(defaults, &stsafe_pkey_def_f.sign_init, &stsafe_pkey_def_f.sign);

    /* Replace those we need to intercept */
    EVP_PKEY_meth_set_init(stsafe_pkey_meth, stsafe_pkey_ec_init);
    EVP_PKEY_meth_set_sign(stsafe_pkey_meth, stsafe_pkey_ec_sign_init, stsafe_pkey_ec_sign);


    DEBUG_PRINTF_API("stsafe_pkey_meth_init finished\n");

    return ENGINE_OPENSSL_SUCCESS;
}



int stsafe_pkey_meth_cleanup(void)
{
    if (stsafe_pkey_meth)
    {
        EVP_PKEY_meth_free(stsafe_pkey_meth);
        stsafe_pkey_meth = NULL;
    }
    return ENGINE_OPENSSL_SUCCESS;
}
