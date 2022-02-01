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


static EVP_PKEY_METHOD * stsafe_pkey_meth;

static int stsafe_pkey_meth_ids[] = { EVP_PKEY_EC, 0 };

/** \brief Check if the eckey provided is one that matches the keys created by/for
the engine */
int stsafe_eckey_is_stsafe_key(EC_KEY * ec)
{
    int ret = ENGINE_OPENSSL_FAILURE;
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    uint16_t CertificateSize = 0;
    int32_t StatusCode = 0;
    StSafeA_LVBuffer_t sts_read_d;
    StSafeA_LVBuffer_t *sts_read = &sts_read_d;
    EC_KEY* stsafe_eckey_pub;
    uint8_t slot;
    unsigned char *key_in, *key_hw;
    int keylen = 0, iii;
    X509 *Cert;
    const unsigned char *CertificatePos;    

    sts_read_d.Data = pStSafeA->InOutBuffer.LV.Data;
    
    for(slot = 0; slot <= 1; slot++)
    {
        /* make sure slot is either 0 or 1 only */
        if(slot > 1) slot = 0;
        
        /* Extract STSAFE-A's X509 CRT certificate */
        StatusCode = StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, slot, 0, 4, 4, sts_read, STSAFEA_MAC_NONE);

        if (StatusCode == 0 && sts_read != NULL)
        {
            switch (sts_read->Data[1])
            {
                case 0x81:
                    CertificateSize = sts_read->Data[2] + 3;
                    break;

                case 0x82:
                    CertificateSize = (((uint16_t)sts_read->Data[2]) << 8) + sts_read->Data[3] + 4;
                    break;

                default:
                    if (sts_read->Data[1] < 0x81)
                    {
                      CertificateSize = sts_read->Data[1];
                    }
                    break;
            }

            StatusCode = StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, slot, 0, CertificateSize, CertificateSize, sts_read, STSAFEA_MAC_NONE);
        }

        /* Parse STSAFE-A's X509 CRT certificate */
        if ((StatusCode == 0) && (sts_read != NULL))
        {
            printf("StSafeA_Read Success CertificateSize = %d\n",CertificateSize);
            CertificatePos = sts_read->Data;
            Cert = d2i_X509/*_AUX*/(NULL, &CertificatePos, CertificateSize);
            
            if(!Cert) continue;

            /* Get Certificate public key */
            EVP_PKEY *CertPublicKey = X509_get_pubkey(Cert);

            if(!CertPublicKey) continue;

            stsafe_eckey_pub = EVP_PKEY_get1_EC_KEY(CertPublicKey);
            OPENSSL_free(CertPublicKey);
        }
        else
        {
            continue;
        }
        
        /* copy the public keys to octet strings and compare */
         
        keylen = EC_KEY_key2buf(ec, POINT_CONVERSION_UNCOMPRESSED, &key_in, NULL);
        printf("\nInput key (len = %d): ", keylen); for(iii = 0; iii< keylen; iii++) printf(" %02x", *(key_in + iii)); printf("\n");
        keylen = EC_KEY_key2buf(stsafe_eckey_pub, POINT_CONVERSION_UNCOMPRESSED, &key_hw, NULL);
        printf("\nSTSafe key (len = %d): ", keylen); for(iii = 0; iii< keylen; iii++) printf(" %02x", *(key_hw + iii)); printf("\n");

        if(key_in && key_hw)
        {
            if(!memcmp(key_hw, key_in, keylen))
            {
                ret = ENGINE_OPENSSL_SUCCESS;
                break;
            }
        }

        if(key_in) OPENSSL_free(key_in);
        if(key_hw) OPENSSL_free(key_hw);
    }

    return ret;
}


/** \brief Check if the pkey provided is one that has been created by/for 
the engine */
int stsafe_pkey_is_stsafe_key(EVP_PKEY * pkey)
{
    int ret = ENGINE_OPENSSL_FAILURE;
    printf("stsafe_pkey_is_stsafe_key called\n");
    if (pkey)
    {
        EC_KEY * ec_key = EVP_PKEY_get1_EC_KEY(pkey);
        if (ec_key)
        {
            ret = stsafe_eckey_is_stsafe_key(ec_key); 
            EC_KEY_free(ec_key);
        }
    }
    printf("stsafe_pkey_is_stsafe_key return =%d\n",ret);
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

    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    EC_KEY           *eckey    = NULL;

    uint16_t CertificateSize = 0;
    int32_t  StatusCode      = 0;

    EC_GROUP *group = NULL;

    StSafeA_LVBuffer_t sts_read_d;
    StSafeA_LVBuffer_t *sts_read = &sts_read_d;
    sts_read_d.Data = pStSafeA->InOutBuffer.LV.Data;

    printf("STSAFE_PKEY> %s called\n", __func__);

    if(!pkey)
    {
        printf("STSAFE_PKEY> %s pkey is NULL so allocate new one\n", __func__);
        pkey = EVP_PKEY_new();
        if(!pkey)
        {
            printf("STSAFE_PKEY> %s EVP_PKEY_new pkey is NULL\n", __func__);
            return NULL;
        }

        if (NULL == (eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
        {
            return NULL;
        }

        /* Note: After this point eckey is associated with pkey and will be
        freed when pkey is freed */
        if (!EVP_PKEY_assign_EC_KEY(pkey, eckey))
        {
            EC_KEY_free(eckey);
            return NULL;
        }
        /* Assign the group info */
        group = (EC_GROUP *)EC_KEY_get0_group(eckey);
        if (group)
        {
            EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);
            EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        }
        
        /* Update the reference counter */
        if(!ENGINE_init(e))
        {
            printf("STSAFE_PKEY> %s Public key load:  Engine init failed\n", __func__);
            return NULL;
        }

        EVP_PKEY_set1_engine(pkey,e);
        EVP_PKEY_set_type(pkey,EVP_PKEY_EC);

        /* Extract STSAFE-A's X509 CRT certificate */
        StatusCode = StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, stsafe_memory_region, 0, 4, 4, sts_read, STSAFEA_MAC_NONE);
        if (StatusCode == 0 && sts_read != NULL)
        {
            switch (sts_read->Data[1])
            {
            case 0x81:
                CertificateSize = sts_read->Data[2] + 3;
                break;

            case 0x82:
                CertificateSize = (((uint16_t)sts_read->Data[2]) << 8) + sts_read->Data[3] + 4;
                break;

            default:
                if (sts_read->Data[1] < 0x81)
                {
                    CertificateSize = sts_read->Data[1];
                }
                break;
            }

            StatusCode = StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, stsafe_memory_region, 0, CertificateSize, CertificateSize, sts_read, STSAFEA_MAC_NONE);
        }

        /* Parse STSAFE-A's X509 CRT certificate */
        if ((StatusCode == 0) && (sts_read != NULL))
        {
            printf("STSAFE_PKEY> %s StSafeA_Read Success CertificateSize = %d\n", __func__, CertificateSize);
            const unsigned char *CertificatePos = sts_read->Data;
            X509 *Cert = d2i_X509/*_AUX*/(NULL, &CertificatePos, CertificateSize);

            /* Get Certificate public key */
            EVP_PKEY *CertPublicKey = X509_get_pubkey(Cert);

            EC_KEY* eckey_pub;
            eckey_pub = EVP_PKEY_get1_EC_KEY(CertPublicKey);
            free(CertPublicKey);
            EVP_PKEY_set1_EC_KEY(pkey,eckey_pub);

        }
    }
    else
    {
        printf("STSAFE_PKEY> %s pkey NOT NULL.\n", __func__);
    }
    
    printf("STSAFE_PKEY> %s returns pkey\n", __func__);
    return pkey;

}


/** \brief Allocate an EVP_PKEY structure and initialize it
This is through the public key API */
EVP_PKEY* stsafe_load_pubkey(ENGINE *e, const char *key_id,
                             UI_METHOD *ui_method, void *callback_data)
{
    (void)ui_method;
    (void)callback_data;
    printf("STSAFE_PKEY> %s called\n", __func__);
    return stsafe_load_pubkey_internal(e, NULL, key_id);
}


/** \brief Allocate an EVP_PKEY structure and initialize it
    This is through the private key API */
EVP_PKEY* stsafe_load_privkey(ENGINE *e, const char *key_id, 
                              UI_METHOD *ui_method, void *callback_data)
{
    (void)ui_method;
    (void)callback_data;
    printf("stsafe_load_privkey called \n");
    return stsafe_load_pubkey_internal(e, NULL, key_id);
}

/** \brief Intercept key initialization and see if the incoming context is a
saved key specific for this device */
int stsafe_pkey_ec_init(EVP_PKEY_CTX *ctx)
{
    printf("stsafe_pkey_ec_init called\n");
    if (ctx)
    {    

        printf("stsafe_pkey_ec_init ctx not NULL \n");
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
                printf("stsafe_pkey_ec_init return ENGINE_OPENSSL_FAILURE \n");
                return ENGINE_OPENSSL_FAILURE;
            }
        }
    }

    printf("stsafe_pkey_ec_init returned\n");
    return stsafe_pkey_def_f.init ? stsafe_pkey_def_f.init(ctx)
        : ENGINE_OPENSSL_SUCCESS;
}


static int stsafe_pkey_ec_sign_init(EVP_PKEY_CTX *ctx)
{

    printf("stsafe_pkey_ec_sign_init called\n");
    return stsafe_pkey_def_f.sign_init ? stsafe_pkey_def_f.sign_init(ctx)
        : ENGINE_OPENSSL_SUCCESS;
}


static int stsafe_pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, 
                               size_t *siglen, const unsigned char *tbs, size_t tbslen)
{

    printf("stsafe_pkey_ec_sign called \n");
    if (stsafe_pkey_is_stsafe_key(EVP_PKEY_CTX_get0_pkey(ctx)))
    {
        printf("stsafe_pkey_ec_sign ---1\n");
        int ret = ENGINE_OPENSSL_FAILURE;
        EC_KEY * ec = EVP_PKEY_get1_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));
        ECDSA_SIG *ecs = NULL;

        do
        {
        
            printf("stsafe_pkey_ec_sign ---signlen=%zd\n",*siglen);
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
            printf("stsafe_pkey_ec_sign ---tbslen=%zd\n",tbslen);
            ecs = stsafe_engine_ecdsa_do_sign(tbs, tbslen, NULL, NULL, ec);

            *siglen = ecs ? i2d_ECDSA_SIG(ecs, &sig): 0;

            ret = ENGINE_OPENSSL_SUCCESS;
        } while (0);

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
    printf("stsafe_pkey_meths called nid=%d\n",nid);
    if (!pkey_meth) {
        *nids = stsafe_pkey_meth_ids;
        return 2;
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
    static const EVP_PKEY_METHOD * defaults;
    printf("stsafe_pkey_meth_init called\n");
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


    printf("stsafe_pkey_meth_init finished\n");

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
