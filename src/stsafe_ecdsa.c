/**
 *********************************************************************************************
 * @file    stsafe_ecdsa.c
 * @author  SMD application team
 * @version V1.0.1
 * @date    08-july-2020
 * @brief   Openssl STSAFE Engine Sign and Verify methods
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
#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include <openssl/rand.h>
#include "openssl/ossl_typ.h"
#include "openssl/obj_mac.h"

#include "ec_local.h"

#include "stsafe_init.h"
#include "stsafe_api.h"
#include "stsafea_types.h"
#include "stsafea_core.h"
#include "stsafea_conf.h"
#include "stsafea_service.h"

#define STS_CHK(ret, f)                     if ((ret) == 0) { ret = f; }

#ifndef STSAFE_ECDH_ENABLE
#define STSAFE_ECDH_ENABLE  1
#endif

#ifndef STSAFE_ECDSA_VERIFY
#define STSAFE_ECDSA_VERIFY 1
#endif

static int32_t stsafe_ec_key_app_data = -1;
static int stsafe_get_curve_detail(EC_KEY *ec, StSafeA_CurveId_t *curve, uint32_t *key_size);
static int stsafe_adjust_hash(int dgst_len, const uint8_t *dgst, int key_size, uint8_t *hash);

int stsafe_engine_ecdsa_sign_setup (EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
    (void)eckey;
    (void)ctx_in;
    (void)kinvp;
    (void)rp;

    return 1;
}


int stsafe_ecc_setappdata(EC_KEY *key, stsafe_ecc_ex_data_t *data)
{
  if (key == NULL)
    return -1;

  if (stsafe_ec_key_app_data == -1)
  {
    DEBUG_PRINTF("%s Module Engine uninitialized\n", __func__);
    return -1;
  }
  DEBUG_PRINTF_API("%s: set app data slot %ld\n", __func__, data->slot);
  
  return EC_KEY_set_ex_data(key, stsafe_ec_key_app_data, data);
}


stsafe_ecc_ex_data_t *stsafe_ecc_getappdata(EC_KEY *key)
{
  if (key == NULL)
    return NULL;

  DEBUG_PRINTF_API("%s: get app data\n", __func__);
  if (stsafe_ec_key_app_data == -1)
  {
    DEBUG_PRINTF("%s Module Engine uninitialized\n", __func__);
    return NULL;
  }
  stsafe_ecc_ex_data_t *data;

  data = EC_KEY_get_ex_data(key, stsafe_ec_key_app_data);
  if (data == NULL)
    return NULL;

  if (data->magic != STSAFE_ECC_APP_DATA_MAGIC)
  {
    DEBUG_PRINTF("%s invalid STSAFE-A ex data\n", __func__);
    return NULL;
  }
  DEBUG_PRINTF_API("%s: get app data slot %ld\n", __func__, data->slot);
  return data;
}

static int stsafe_adjust_hash(int dgst_len, const uint8_t *dgst, int key_size, uint8_t *hash)
{
	memset(hash, 0, key_size);
	if (key_size != dgst_len)
	{
    if (dgst_len >= key_size){
      /* for truncated hash no need to recopy, only adjust the hash size as leftmost significant bytes are kept */
      dgst_len = key_size;
			memcpy(hash, dgst, dgst_len);
    }
    if (dgst_len < key_size){
      /* if hash is too small, need to left pad with 0 */
      memcpy(hash + (key_size - dgst_len), dgst, dgst_len);
			dgst_len = key_size;
		}
	}
	else
		memcpy(hash, dgst, dgst_len);
	return dgst_len;
}


ECDSA_SIG *stsafe_engine_ecdsa_do_sign (const unsigned char *dgst, int dgst_len,
                                        const BIGNUM *kinv, const BIGNUM *rp,
                                        EC_KEY *in_eckey)
{
    (void)in_eckey;
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    DEBUG_PRINTF("%s digest_len = %d\n", __func__, dgst_len);
    if (kinv != NULL) {
        DEBUG_PRINTF("%s kinv = ", __func__);
        DEBUG_BN_PRINTF(stdout, kinv);
    }
    if (rp != NULL) {
        DEBUG_PRINTF("%s rp   = ", __func__);
        DEBUG_BN_PRINTF(stdout, rp);
    }
    int32_t StatusCode = 0;
		uint8_t l_hash[48] = {0};
    ECDSA_SIG *EcdsaSignature = NULL ;
    StSafeA_LVBuffer_t OutR;
    StSafeA_LVBuffer_t OutS;
    stsafe_ecc_ex_data_t *data;
		uint32_t key_size;
		StSafeA_CurveId_t curve;

    if (kinv != NULL || rp != NULL)
            return (NULL);

    /* check if this is an STSAFE-A key */
    data = stsafe_ecc_getappdata(in_eckey);
    if (data->slot == -1)
    {
      /* not an STSAFE-A key */
      DEBUG_PRINTF_ERROR("%s : error while getting extended data\n", __func__);
      return NULL;  
    }
		
		if (stsafe_get_curve_detail(in_eckey, &curve, &key_size) == 0)
		{
      DEBUG_PRINTF_ERROR("%s : error while getting curve detail\n", __func__);
	    return NULL;
		}

		key_size = stsafe_adjust_hash(dgst_len, (uint8_t*)dgst, key_size, l_hash);

    /* Generate signature of Hash(random) */
    uint8_t data_OutR [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
    uint8_t data_OutS [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
    OutR.Data = data_OutR;
    OutS.Data = data_OutS;

	  DEBUG_PRINTF("%s : key_size = %d dgst_size = %d, curve = %d\n", __func__, key_size, dgst_len, curve);
    StatusCode = StSafeA_GenerateSignature(pStSafeA, data->slot, l_hash,
                                           (key_size == 48 ? STSAFEA_SHA_384 : STSAFEA_SHA_256),
                                           key_size,
                                           &OutR, &OutS, STSAFEA_MAC_NONE, STSAFEA_ENCRYPTION_NONE);

    /* Verify signature */
    if (StatusCode == 0)
    {
        /* Build both R & S signature */
        uint16_t RLength = OutR.Length;
        uint16_t SLength = OutS.Length;

        DEBUG_PRINTF("StSafeA_GenerateSignature : RLength=%d SLength=%d\n",RLength,SLength);   
        BIGNUM *r;
        BIGNUM *s;
       
        STS_CHK(StatusCode, (EcdsaSignature = ECDSA_SIG_new()) ? 0 : 1);
        STS_CHK(StatusCode, (r = BN_new()) ? 0 : 1);
        STS_CHK(StatusCode, (s = BN_new()) ? 0 : 1);
        STS_CHK(StatusCode, BN_bin2bn(OutR.Data, RLength, r) ? 0 : 1);
        STS_CHK(StatusCode, BN_bin2bn(OutS.Data, SLength, s) ? 0 : 1);
        ECDSA_SIG_set0(EcdsaSignature,r,s);

        DEBUG_PRINTF("\n\nInput Hash size:%d \n",dgst_len);
        for(int i=0; i <dgst_len;i++) {
          DEBUG_PRINTF("%02x",dgst[i]);
        }

        DEBUG_PRINTF("\n\nSignature R size:%d \n",RLength);
        for(int i=0; i <RLength;i++) {
          DEBUG_PRINTF("%02x",data_OutR[i]);
        }

        DEBUG_PRINTF("\nSignature S size:%d \n",SLength);
        for(int i=0; i <SLength;i++) {
          DEBUG_PRINTF("%02x",data_OutS[i]);
        }
        DEBUG_PRINTF("\n\n");


    }
    else
    {
      DEBUG_PRINTF_ERROR("%s : STSAFE-A error %x\n", __func__, StatusCode);
    }

    return EcdsaSignature;
}

int stsafe_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                      unsigned char *sig, unsigned int *siglen,
                      const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    (void)type;

    ECDSA_SIG *s;

    DEBUG_PRINTF("stsafe_ecdsa_sign called\n");

    if ((dgst == NULL ||
                 dlen <= 0)) { /* Check these input params before passing to
                                * RAND_seed(). Rest of the input params. are
                                * checked by stsafe_engine_ecdsa_do_sign().
                                */
        DEBUG_PRINTF("Invalid input param.\n");
        if (siglen != NULL)
            *siglen = 0;
        return 0;
    }
    RAND_seed(dgst, dlen);
    s = stsafe_engine_ecdsa_do_sign(dgst, dlen, kinv, r, eckey);
    if (s == NULL) {
        DEBUG_PRINTF("Error ECDSA Sign Operation Failed\n");
        if (siglen != NULL)
            *siglen = 0;
        return 0;
    }
    *siglen = i2d_ECDSA_SIG(s, &sig);

    DEBUG_PRINTF("stsafe_ecdsa_sign : DER encoding sign_len=%d\n",*siglen);
    ECDSA_SIG_free(s);
    return 1;
}

static int stsafe_get_curve_detail(EC_KEY *ec, StSafeA_CurveId_t *curve, uint32_t *key_size)
{
    uint32_t  OpensslCurveId = 0;

		const EC_GROUP *group = EC_KEY_get0_group(ec);

    OpensslCurveId = EC_GROUP_get_curve_name(group);

    if (OpensslCurveId != NID_undef) {
      if ( (OpensslCurveId == NID_X9_62_prime256v1) ||
	         (OpensslCurveId == NID_secp256k1) ) {
			  *curve = STSAFEA_NIST_P_256;
		    *key_size = 32;
				DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Curve %s -> STSAFEA_NIST_P_256\n", __func__, OBJ_nid2sn(OpensslCurveId));
	    }
	    else if (OpensslCurveId == NID_secp384r1) {
		    *curve = STSAFEA_NIST_P_384;
		    *key_size = 48;
		    DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Curve %s -> STSAFEA_NIST_P_384\n", __func__, OBJ_nid2sn(OpensslCurveId));
	    }
	    else if ( (OpensslCurveId == NID_brainpoolP256r1) ||
			    (OpensslCurveId == NID_brainpoolP256t1) ) {
		    *curve = STSAFEA_BRAINPOOL_P_256;
		    *key_size = 32;
		    DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Curve %s -> STSAFEA_BRAINPOOL_P_256\n", __func__, OBJ_nid2sn(OpensslCurveId));
	    }
	    else if ( (OpensslCurveId == NID_brainpoolP384r1) ||
			    (OpensslCurveId == NID_brainpoolP384t1) ) {
		    *curve = STSAFEA_BRAINPOOL_P_384;
		    *key_size = 48;
		    DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Curve %s -> STSAFEA_BRAINPOOL_P_384\n", __func__, OBJ_nid2sn(OpensslCurveId));
	    } else {
		    DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Error unsupported curve %s\n", __func__, OBJ_nid2sn(OpensslCurveId));
				return 0;
			}
			return 1;
		}
	return 0;
}
//  secureProtocol:crypto.constants.SSL_OP_NO_TLSv1_3
int stsafe_engine_ecdsa_do_verify (const unsigned char *digest, int digest_len,
                                   const ECDSA_SIG *ecdsa_sig, EC_KEY *eckey) {
            
    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    
    int res = 0;
    uint32_t sig_len = 64;
    int32_t StatusCode = 0;
    uint8_t *raw_pubkey = NULL;
    size_t len = 0;
    point_conversion_form_t form;
    StSafeA_LVBuffer_t Sig_R_d;
    StSafeA_LVBuffer_t Sig_S_d;
    StSafeA_LVBuffer_t *Sig_R = &Sig_R_d;
    StSafeA_LVBuffer_t *Sig_S = &Sig_S_d;
    StSafeA_VerifySignatureBuffer_t Verif_d;
    StSafeA_VerifySignatureBuffer_t *Verif = &Verif_d;
	  StSafeA_CurveId_t InCurveId = STSAFEA_NIST_P_256;
    
    uint8_t data_Sig_R_d [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
    Sig_R_d.Data = data_Sig_R_d;
    uint8_t data_Sig_S_d [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
    Sig_S_d.Data = data_Sig_S_d;

    DEBUG_PRINTF("%s called\n", __func__);

    const BIGNUM *sig_r = NULL;
    const BIGNUM *sig_s = NULL;

		if( stsafe_get_curve_detail(eckey, &InCurveId, &sig_len) == 0) {
			DEBUG_PRINTF_ERROR("%s unable to get curve details", __func__);
			goto done;
		}
		sig_len *=2;
    
    ECDSA_SIG_get0((ECDSA_SIG *)ecdsa_sig, &sig_r, &sig_s);
 
    if( BN_is_zero(sig_r) ||
        BN_is_negative(sig_r) ||
        BN_is_zero(sig_s) ||
        BN_is_negative(sig_s) )
    {
        DEBUG_PRINTF("%s ECDSA_SIG sig is invalid\n", __func__);
        goto done;
    }

    Sig_R->Length = BN_num_bytes(sig_r);
    if (Sig_R->Length > sig_len / 2) {
        goto done;
    }
    Sig_S->Length = BN_num_bytes(sig_s);
    if (Sig_S->Length > sig_len / 2) {
        goto done;
    }
    (void)BN_bn2bin(sig_r, Sig_R->Data);
    (void)BN_bn2bin(sig_s, Sig_S->Data);
    
		const EC_GROUP *group = EC_KEY_get0_group(eckey);
   
	  form = EC_GROUP_get_point_conversion_form(group);
		
		/* Get the raw form length requirements */
    len = EC_POINT_point2oct(group, EC_KEY_get0_public_key(eckey), form, NULL, len, NULL);

    raw_pubkey = (uint8_t *)OPENSSL_malloc(len);
    if (raw_pubkey == NULL) {
        goto done;
    }

    /* Convert to raw form */
    if (EC_KEY_get0_public_key(eckey)) {
        EC_POINT_point2oct(group, EC_KEY_get0_public_key(eckey), form, raw_pubkey, len, NULL);
    }
    
    /* Store public key */
    StSafeA_LVBuffer_t X_d;
    StSafeA_LVBuffer_t *X = &X_d; 
    X_d.Data = OPENSSL_malloc(len/2);
   
    if (X->Data != NULL)
    {
      X->Length = len/2 ;
      memcpy(X->Data, (raw_pubkey +1 ), X->Length);
    }

    StSafeA_LVBuffer_t Y_d;
    StSafeA_LVBuffer_t *Y = &Y_d; 
    Y_d.Data = OPENSSL_malloc(len/2);

    if (Y->Data != NULL)
    {
      Y->Length = len/2 ;
      memcpy(Y->Data, (raw_pubkey + 1 +  X->Length ), Y->Length);
    }
  
    StSafeA_LVBuffer_t SH_d;
    StSafeA_LVBuffer_t *SH = &SH_d; 
    SH_d.Data = OPENSSL_malloc(sig_len/2);
		SH->Length = stsafe_adjust_hash(digest_len, digest, sig_len/2, SH->Data);

   StatusCode =  StSafeA_VerifyMessageSignature(pStSafeA, InCurveId, X, Y, Sig_R, Sig_S, SH , Verif, STSAFEA_MAC_NONE); 


   DEBUG_PRINTF("StSafeA_VerifyMessageSignature called, StatusCode:%d SignatureValidity=%d\n",StatusCode,Verif->SignatureValidity); 
   if ((StatusCode == 0) && (Verif != NULL) && (Verif->SignatureValidity == 0))
   {
     res = 0;
   }
   else
   {
    /* Correct Signature*/
    res =1;
   }

done:
		if (SH->Data) OPENSSL_free(SH->Data);
		if (X->Data) OPENSSL_free(X->Data);
		if (Y->Data) OPENSSL_free(Y->Data);
		if (raw_pubkey) OPENSSL_free(raw_pubkey);

    DEBUG_PRINTF("stsafe ecdsa verfiy end! result %d %x\n",res, StatusCode);
    return res;
}

/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int stsafe_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                        const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    (void)type;

    ECDSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    DEBUG_PRINTF("Engine: stsafe_ecdsa_verify called siglen=%d\n",sig_len);
    s = ECDSA_SIG_new();
    if (s == NULL) {
        DEBUG_PRINTF("Failure to allocate ECDSA_SIG s\n");
        return (ret);
    }
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL) {
        DEBUG_PRINTF("Failure to convert sig_buf and sig_len to s\n");
        goto err;
    }
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen) != 0) {
        DEBUG_PRINTF("Failure ECDSA_SIG s contains trailing garbage\n");
        goto err;
    }
     DEBUG_PRINTF("Engine: stsafe_ecdsa_verify derlen=%d dgst_len=%d\n",derlen,dgst_len);
    ret = stsafe_engine_ecdsa_do_verify(dgst, dgst_len, s, eckey);
 err:
    OPENSSL_clear_free(der, derlen);
    ECDSA_SIG_free(s);

    DEBUG_PRINTF("Engine: stsafe_ecdsa_verify return\n");
    return ret;
}

int
stsafe_ecdh_compute_key(unsigned char **outX, size_t *outlenX,
                        unsigned char **outY, size_t *outlenY,
                        const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    (void)outY;
    (void)outlenY;

    const EC_GROUP *group  = NULL;

    uint8_t  *raw_pubkey = NULL;
    int32_t   ret        = 0;
    int32_t   StatusCode = 0;
    size_t    len        = 0;

    int stsafe_gen_key_slot;
    stsafe_ecc_ex_data_t *data;
    data = stsafe_ecc_getappdata((EC_KEY*)ecdh);
    if (data == NULL) {
      DEBUG_PRINTF_ERROR("STSAFE-EC> %s: invalid key\n", __func__);
      return ret;
    }
    stsafe_gen_key_slot = (int)data->slot; 


    StSafeA_LVBuffer_t HostCX_d;
    StSafeA_LVBuffer_t HostCY_d;
    StSafeA_SharedSecretBuffer_t SharedSecret_d;
    StSafeA_LVBuffer_t *HostCX = &HostCX_d;
    StSafeA_LVBuffer_t *HostCY = &HostCY_d; 
    StSafeA_SharedSecretBuffer_t *SharedSecret = &SharedSecret_d; 

    StSafeA_Handle_t *pStSafeA = &stsafea_handle;
    
    point_conversion_form_t form = { 0 };

    

    DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Using Slot %d\n", __func__, stsafe_gen_key_slot);

    if( (ecdh == NULL) ||
        (pub_key == NULL) ) {
        DEBUG_FPRINTF(stderr, "STSAFE-EC> %s: Error ecdh %p pub_key %p\n",
                __func__, ecdh, pub_key);
        return ret;
    }

    if ((group = EC_KEY_get0_group(ecdh)) == NULL) {
        DEBUG_FPRINTF(stderr, "STSAFE-EC> %s: Error group %p\n", __func__, group);
        return ret;
    }

    form = EC_GROUP_get_point_conversion_form(group);
    len  = EC_POINT_point2oct(group, pub_key, form, NULL, 0, NULL);
 
    DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: EC_POINT_point2oct len %zd\n", __func__, len);

    if (len == 0) {
        DEBUG_FPRINTF(stderr, "STSAFE-EC> %s: Error EC_POINT_point2oct len %zd\n", __func__, len);
        goto done;
    }

    raw_pubkey = (uint8_t *)OPENSSL_malloc(len);
    if (raw_pubkey == NULL) {
        DEBUG_FPRINTF(stderr, "STSAFE-EC> %s: Error OPENSSL_malloc returned NULL\n", __func__);
        goto done;
    }

    /* Convert to raw form */
    if(!EC_POINT_point2oct(group, pub_key, form, raw_pubkey, len, NULL)) {
        DEBUG_FPRINTF(stderr, "STSAFE-EC> %s: Error EC_POINT_point2oct\n", __func__);
        goto done;
    }

    /* Store public key */
    HostCX->Data = OPENSSL_malloc(len/2);
    if (HostCX->Data != NULL) {
        HostCX->Length = len/2 ;
        memcpy(HostCX->Data, (raw_pubkey +1 ), HostCX->Length);
        *outlenX = HostCX->Length;
    } else {
        DEBUG_FPRINTF(stderr, "STSAFE-EC> %s: Error OPENSSL_malloc returned NULL\n", __func__);
        goto done;
    }

    HostCY->Data = OPENSSL_malloc(len/2);
    if (HostCY->Data != NULL) {
        HostCY->Length = len/2 ;
        memcpy(HostCY->Data, (raw_pubkey + 1 +  HostCX->Length ), HostCY->Length);
    } else {
        DEBUG_FPRINTF(stderr, "STSAFE-EC> %s: Error OPENSSL_malloc returned NULL\n", __func__);
        goto done;
    }

    uint16_t keylength = STSAFEA_XYRS_ECDSA_SHA256_LENGTH;
#if defined (NIST_P_256) || defined (BRAINPOOL_P_256)
    keylength = STSAFEA_XYRS_ECDSA_SHA256_LENGTH;
#elif defined (NIST_P_384) || defined (BRAINPOOL_P_384)
    keylength = STSAFEA_XYRS_ECDSA_SHA384_LENGTH;
#endif

    keylength = len/2;

    SharedSecret->SharedKey.Data = pStSafeA->InOutBuffer.LV.Data;
    
    DEBUG_FPRINTF(stdout, "Before calling StSafeA_EstablishKey.\n");
    
    uint8_t inmac = STSAFEA_MAC_HOST_CMAC;
    uint8_t hostmac_flag = STSAFEA_ENCRYPTION_RESPONSE;
#if defined(STSAFE_A110)          
    inmac = STSAFEA_MAC_NONE;
    hostmac_flag = STSAFEA_ENCRYPTION_NONE;
#endif
    if (get_cmd_auth_enc(STSAFEA_ESTABLISH, &inmac, &hostmac_flag) != 0)
    {
        DEBUG_FPRINTF(stderr, "STSAFE> %s: Estalbish key configuration unknown \n", __func__);
    }
    
    StatusCode = StSafeA_EstablishKey(pStSafeA, stsafe_gen_key_slot, HostCX, HostCY, keylength, SharedSecret, inmac, hostmac_flag);
    DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: StatusCode = %d, outlen = %zd\n", __func__, StatusCode, *outlenX);
    if (StatusCode == STSAFEA_OK) {
        /* allocate openssl buffer for secret, this will be freed in ec_kmeth.c after use */
        *outX = OPENSSL_malloc((*outlenX) * sizeof(char));
        if (*outX == NULL) {
            DEBUG_FPRINTF(stderr, "STSAFE> %s: OPENSSL_malloc returned NULL\n", __func__);
            goto done;
        }
        memcpy(*outX, SharedSecret->SharedKey.Data, *outlenX);
    }
    else
    {
        ret = 0;
        *outX = NULL;
        goto done;
    }
    ret = 1;

done:

    if (HostCX->Data) OPENSSL_free(HostCX->Data);
    if (HostCY->Data) OPENSSL_free(HostCY->Data);

    return ret;
}

int stsafe_engine_ecdh_compute_key(unsigned char **out,
                                size_t *outlen,
                                const EC_POINT *pub_key,
                                const EC_KEY *ecdh)
{
    DEBUG_PRINTF("stsafe_engine_ecdh_compute_key called\n");
    return stsafe_ecdh_compute_key(out, outlen, NULL, NULL, pub_key, ecdh);
}

uint8_t get_mac(uint8_t slot)
{
	StSafeA_Handle_t *pStSafeA = &stsafea_handle;
	StSafeA_ResponseCode_t status_code = STSAFEA_OK;
	StSafeA_TLVBuffer_t inCmd;
	uint8_t data[100];
	StSafeA_TLVBuffer_t outTLV;
	outTLV.LV.Data = data;
	outTLV.LV.Length = sizeof(data);

	uint8_t res = 0xFF;

	inCmd.Header = 0x14;
	inCmd.LV.Data = data;
	data[0] = 0x14;
	inCmd.LV.Length = 1;

	/* get slot 0 key size */
	status_code = StSafeA_RawCommand(pStSafeA, &inCmd, sizeof(data), &outTLV, 10, STSAFEA_MAC_NONE);
	if (status_code == STSAFEA_OK)
	{
		if (outTLV.Header == 0x00)
		{
			uint8_t offset = 4;
			if (slot == 0)
			{
				res = ((outTLV.LV.Data[offset + 3] & 0x30) == 0 ? STSAFEA_MAC_NONE : STSAFEA_MAC_HOST_CMAC);
				return res;
			}
			if (outTLV.LV.Data[offset + 1] & 0x1)
			{
				offset += outTLV.LV.Data[offset + 5] + 6;
			}
			else
			{
				offset += 4;
			}
			if (slot == 1)
			{
				res = ((outTLV.LV.Data[offset + 3] & 0x30) == 0 ? STSAFEA_MAC_NONE : STSAFEA_MAC_HOST_CMAC);
				return res;
			}
			if (outTLV.LV.Data[offset + 1] & 0x1)
			{
				offset += outTLV.LV.Data[offset + 5] + 6;
			}
			else
			{
				offset += 4;
			}
			if (slot == 0xFF)
			{
				res = ((outTLV.LV.Data[offset + 3] & 0x30) == 0 ? STSAFEA_MAC_NONE : STSAFEA_MAC_HOST_CMAC);
				return res;
			}
			if (outTLV.LV.Data[offset + 1] & 0x1)
			{
				offset += outTLV.LV.Data[offset + 5] + 6;
			}
			else
			{
				offset += 4;
			}
		}
	}
	return res;
}


#if !STSAFE_ECDH_ENABLE
int (*default_ec_generate_key)(EC_KEY *eckey) = NULL;
#endif
/**
 * @brief stsafe_ec_generate_key
 * @param eckey
 * @return
 */
int
stsafe_ec_generate_key(EC_KEY *eckey)
{
    BIGNUM   *X       = NULL;
    BIGNUM   *Y       = NULL;

    char          opensslerrbuff[1024];
    unsigned long opensslerr;

    StSafeA_CurveId_t           InCurveId = STSAFEA_NIST_P_256;
    StSafeA_ResponseCode_t      RespCode  = STSAFEA_OK;

    StSafeA_LVBuffer_t PubCX_d;
    StSafeA_LVBuffer_t *PubCX = &PubCX_d; 
    StSafeA_LVBuffer_t PubCY_d;
    StSafeA_LVBuffer_t *PubCY = &PubCY_d; 
    

    StSafeA_Handle_t *pStSafeA = &stsafea_handle;

    uint8_t   PointReprensentationId = 0;
    uint32_t  OpensslCurveId         = 0;
    int32_t   retval                 = 0;
    uint16_t  xylength               = 0;

    PubCX_d.Data = NULL;
    PubCY_d.Data = NULL;
    /*
     * The slot number is by default 0xff, which is used for ephemeral key use, thus it works
     * from OpenSSL APIs used for TLS etc. When the OpenSSL CLI application is used the keyslot
     * can be changed for non epehmeral key setting. An API is provided so users can use the
     * engine in their own applications and set the slot using the provided API before key
     * generation or sign/verify.
     */

    DEBUG_PRINTF("STSAFE-EC> %s called. %p\n", __func__, eckey);

    DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Using Slot %ld\n", __func__, stsafe_gen_key_slot);

    if (eckey == NULL) {
        DEBUG_FPRINTF(stderr, "STSAFE-EC> %s: eckey is NULL\n", __func__);
        goto err;
    }
#if !STSAFE_ECDH_ENABLE
    if (stsafe_gen_key_slot == STSAFEA_KEY_SLOT_EPHEMERAL)
    {
	if (default_ec_generate_key)
	    return default_ec_generate_key(eckey);
	return -1;
    }
#endif


    if (stsafe_gen_key_slot == 0) {

      StSafeA_Handle_t *pStSafeA = &stsafea_handle;

      uint16_t CertificateSize = 0;
      int32_t  StatusCode      = 0;

      StSafeA_LVBuffer_t sts_read_d;
      StSafeA_LVBuffer_t *sts_read = &sts_read_d;
      sts_read_d.Data = pStSafeA->InOutBuffer.LV.Data;
    
      stsafe_ecc_ex_data_t *data;

      retval = -1;


      data = OPENSSL_malloc(sizeof(stsafe_ecc_ex_data_t));
      if (data == NULL) {
        DEBUG_PRINTF_ERROR("STSAFE_EC> %s alloc error\n", __func__);
        return retval;
      }
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
        DEBUG_PRINTF_API("STSAFE_PKEY> %s StSafeA_Read Success CertificateSize = %d\n", __func__, CertificateSize);
        const unsigned char *CertificatePos = sts_read->Data;
        X509 *Cert = d2i_X509(NULL, &CertificatePos, CertificateSize);

	
        /* Get Certificate public key */
        EVP_PKEY *CertPublicKey = X509_get_pubkey(Cert);

	X509_free(Cert);
        EC_KEY_copy(eckey, EVP_PKEY_get1_EC_KEY(CertPublicKey));
        EVP_PKEY_free(CertPublicKey);
        

        data->slot = 0;
        data->magic = STSAFE_ECC_APP_DATA_MAGIC;
        memcpy(data->serial, stsafe_get_serial(), 9);

        if (stsafe_ecc_setappdata(eckey, data) == 0)
          goto err;
        
        retval = 1;
      }
    }
    else
    {

      /* convert from ec_key curve details to StSafeA_CurveId InCurveId
       * if prime256v1 | secp256k1 -> STSAFEA_NIST_P_256
       * if secp384r1              -> STSAFEA_NIST_P_384
       * if brainpoolP256r1 | brainpoolP256t1 -> STSAFEA_BRAINPOOL_P_256
       * if brainpoolP384r1 | brainpoolP256t1 -> STSAFEA_BRAINPOOL_P_384 
       */
      OpensslCurveId = EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey));

      if (OpensslCurveId != NID_undef) {
        if ( (OpensslCurveId == NID_X9_62_prime256v1) ||
            (OpensslCurveId == NID_secp256k1) ) {
          InCurveId = STSAFEA_NIST_P_256;
          xylength = STSAFEA_GET_XYRS_LEN_FROM_CURVE(STSAFEA_NIST_P_256);
          DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Curve %s -> STSAFEA_NIST_P_256\n", __func__, OBJ_nid2sn(OpensslCurveId));
        }
        else if (OpensslCurveId == NID_secp384r1) {
          InCurveId = STSAFEA_NIST_P_384;
          xylength = STSAFEA_GET_XYRS_LEN_FROM_CURVE(STSAFEA_NIST_P_384);
          DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Curve %s -> STSAFEA_NIST_P_384\n", __func__, OBJ_nid2sn(OpensslCurveId));
        }
        else if ( (OpensslCurveId == NID_brainpoolP256r1) ||
            (OpensslCurveId == NID_brainpoolP256t1) ) {
          InCurveId = STSAFEA_BRAINPOOL_P_256;
          xylength = STSAFEA_GET_XYRS_LEN_FROM_CURVE(STSAFEA_BRAINPOOL_P_256);
          DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Curve %s -> STSAFEA_BRAINPOOL_P_256\n", __func__, OBJ_nid2sn(OpensslCurveId));
        }
        else if ( (OpensslCurveId == NID_brainpoolP384r1) ||
            (OpensslCurveId == NID_brainpoolP384t1) ) {
          InCurveId = STSAFEA_BRAINPOOL_P_384;
          xylength = STSAFEA_GET_XYRS_LEN_FROM_CURVE(STSAFEA_BRAINPOOL_P_384);
          DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Curve %s -> STSAFEA_BRAINPOOL_P_384\n", __func__, OBJ_nid2sn(OpensslCurveId));
        } else {
          DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Error unsupported curve %s\n", __func__, OBJ_nid2sn(OpensslCurveId));
          goto err;
        }
      } else {
        DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Error undefined curve\n", __func__);
        goto err;
      }

      PubCX_d.Data = OPENSSL_malloc(xylength);
      PubCY_d.Data = OPENSSL_malloc(xylength);
      if((PubCX_d.Data == NULL) || (PubCY_d.Data == NULL))
      {
        DEBUG_FPRINTF(stderr, "STSAFE-EC> %s: Error StSafeA_GenerateKeyPair failed to allocate required memory.\n", __func__);
        goto err;
      }

      PubCX_d.Length = xylength;
      PubCY_d.Length = xylength;
      uint8_t inmac = STSAFEA_MAC_HOST_CMAC;
#if defined(STSAFE_A110)          
      inmac = get_mac(stsafe_gen_key_slot);
#endif

      


      uint16_t limit = 0xFFFF;
      if (stsafe_gen_key_slot == 0xFF)
	limit = 1;
      else
	limit = 0xFFFF;
      RespCode = StSafeA_GenerateKeyPair( pStSafeA,
          (uint8_t)stsafe_gen_key_slot,
          limit,
          0,
          0,
          InCurveId,
          xylength,
          &PointReprensentationId,
          PubCX,
          PubCY,
          inmac);

      if (RespCode != STSAFEA_OK) {
        DEBUG_FPRINTF(stderr, "STSAFE-EC> %s: Error StSafeA_GenerateKeyPair failed 0x%02x\n", __func__, RespCode);
        goto err;
      }

      DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: X:Length %d Data ", __func__, PubCX->Length);
      for (int i = 0; i < PubCX->Length; i++) {
        DEBUG_FPRINTF(stdout, "0x%02x ", PubCX->Data[i]);
      }
      DEBUG_FPRINTF(stdout, "\n");

      DEBUG_FPRINTF(stdout, "STSAFE-EC> %s: Y:Length %d Data ", __func__, PubCY->Length);
      for (int i = 0; i < PubCY->Length; i++) {
        DEBUG_FPRINTF(stdout, "0x%02x ", PubCY->Data[i]);
      }
      DEBUG_FPRINTF(stdout, "\n");

      /* convert X,Y into OpenSSL BIGNUM format */
      if ((X = BN_bin2bn(PubCX->Data, PubCX->Length, NULL)) == NULL) {
        opensslerr = ERR_get_error();
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
          DEBUG_FPRINTF(stderr, "ECKEYGEN> %s: BN_hex2bn error %ld %s\n", __func__, opensslerr, opensslerrbuff);
          goto err;
        }
      }

      if ((Y = BN_bin2bn(PubCY->Data, PubCY->Length, NULL)) == NULL) {
        opensslerr = ERR_get_error();
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
          DEBUG_FPRINTF(stderr, "ECKEYGEN> %s: BN_hex2bn error %ld %s\n", __func__, opensslerr, opensslerrbuff);
          goto err;
        }
      }

      DEBUG_PRINTF_API("ECKEYGEN> %s: set public key affine : ", __func__);
      if (!EC_KEY_set_public_key_affine_coordinates(eckey, X, Y)) {
        opensslerr = ERR_get_error();
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
          DEBUG_FPRINTF(stderr, "ECKEYGEN> %s: EC_KEY_set_public_key_affine_coordinates error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        goto err;
      }
      DEBUG_PRINTF_API("OK\n");
      stsafe_ecc_ex_data_t *data;
      data = stsafe_ecc_getappdata(eckey);

      if (data == NULL)
      {
        data = OPENSSL_malloc(sizeof(*data));
        if (data == NULL) {
          DEBUG_PRINTF_ERROR("ECKEYGEN> %s: context allocation error\n", __func__);
          goto err;
        }
      }
      data->magic = STSAFE_ECC_APP_DATA_MAGIC;
      data->slot = stsafe_gen_key_slot;
      memcpy(data->serial, stsafe_get_serial(), 9);    

      retval = stsafe_ecc_setappdata(eckey, data);
      if (retval == 0)
      {
        DEBUG_PRINTF_ERROR("ECKEYGEN> %s: unable to set extra data to ec key\n", __func__);
        goto err;
      }
      retval = 1;
    }
    
    DEBUG_PRINTF_API("ECKEYGEN> %s: exit\n", __func__);
    goto no_err;
err:
    
    DEBUG_PRINTF_API("ECKEYGEN> %s: exit err %p, %p, %p, %p\n", __func__, X, Y, PubCX_d.Data, PubCY_d.Data);
    if (X) BN_free(X);
    if (Y) BN_free(Y);
no_err:
    if (PubCX_d.Data) OPENSSL_free(PubCX_d.Data);
    if (PubCY_d.Data) OPENSSL_free(PubCY_d.Data);

    DEBUG_PRINTF_API("ECKEYGEN> %s: exit no err %p, %p, %p, %p\n", __func__, X, Y, PubCX_d.Data, PubCY_d.Data);
    return retval;
}

EC_KEY_METHOD *stsafe_engine_ec_method = NULL;


EC_KEY_METHOD *stsafe_get_EC_methods(void)
{
   const EC_KEY_METHOD *defaults = NULL;
   DEBUG_PRINTF("stsafe_get_EC_methods called \n");
   defaults = EC_KEY_OpenSSL();
    if (stsafe_engine_ec_method != NULL)
        return stsafe_engine_ec_method;

    if ((stsafe_engine_ec_method = EC_KEY_METHOD_new(defaults)) == NULL) {
        DEBUG_PRINTF("Unable to allocate stsafe engine EC_KEY_METHOD\n");
        return NULL;
    }      

    DEBUG_PRINTF("EC_KEY_METHOD_set_sign.\n");
    EC_KEY_METHOD_set_sign(stsafe_engine_ec_method, stsafe_ecdsa_sign, NULL, stsafe_engine_ecdsa_do_sign);
#if STSAFE_ECDSA_VERIFY 
    DEBUG_PRINTF("EC_KEY_METHOD_set_verify.\n");
    EC_KEY_METHOD_set_verify(stsafe_engine_ec_method, stsafe_ecdsa_verify, stsafe_engine_ecdsa_do_verify);
#endif
    DEBUG_PRINTF("EC_KEY_METHOD_set_keygen.\n");
#if !STSAFE_ECDH_ENABLE
    EC_KEY_METHOD_get_keygen(stsafe_engine_ec_method, &default_ec_generate_key);
#endif
    EC_KEY_METHOD_set_keygen(stsafe_engine_ec_method, stsafe_ec_generate_key);

#if STSAFE_ECDH_ENABLE
    DEBUG_PRINTF("EC_KEY_METHOD_set_compute_key.\n");
    EC_KEY_METHOD_set_compute_key(stsafe_engine_ec_method, stsafe_engine_ecdh_compute_key);
#endif
     if (stsafe_ec_key_app_data == -1)
        stsafe_ec_key_app_data = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, NULL); 
    return stsafe_engine_ec_method;
}

void stsafe_release_EC_methods(void)
{
  if (stsafe_engine_ec_method != NULL)
    EC_KEY_METHOD_free(stsafe_engine_ec_method);
}



