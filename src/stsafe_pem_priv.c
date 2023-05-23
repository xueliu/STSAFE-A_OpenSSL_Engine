
#include <stdio.h>
#include <string.h>


#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/rand.h>

#include "stsafe_api.h"

typedef struct {
	ASN1_INTEGER *serial;
  ASN1_OBJECT *curve;
	ASN1_INTEGER *pubkeyx;
	ASN1_INTEGER *pubkeyy;
	ASN1_INTEGER *slot;
  ASN1_INTEGER *tag;
} STSAFEPRIVKEY;


DECLARE_ASN1_FUNCTIONS(STSAFEPRIVKEY);

ASN1_SEQUENCE(STSAFEPRIVKEY) = {
	ASN1_SIMPLE(STSAFEPRIVKEY, serial, ASN1_INTEGER),
  ASN1_SIMPLE(STSAFEPRIVKEY, curve, ASN1_OBJECT),
	ASN1_SIMPLE(STSAFEPRIVKEY, pubkeyx, ASN1_INTEGER),
	ASN1_SIMPLE(STSAFEPRIVKEY, pubkeyy, ASN1_INTEGER),
	ASN1_SIMPLE(STSAFEPRIVKEY, slot, ASN1_INTEGER),
	ASN1_SIMPLE(STSAFEPRIVKEY, tag, ASN1_INTEGER)
} ASN1_SEQUENCE_END(STSAFEPRIVKEY)

#define STSAFEPRIVKEY_PEM_STRING "STSAFE KEY"

IMPLEMENT_ASN1_FUNCTIONS(STSAFEPRIVKEY);
IMPLEMENT_PEM_write_bio(STSAFEPRIVKEY, STSAFEPRIVKEY, STSAFEPRIVKEY_PEM_STRING, STSAFEPRIVKEY);
IMPLEMENT_PEM_read_bio(STSAFEPRIVKEY, STSAFEPRIVKEY, STSAFEPRIVKEY_PEM_STRING, STSAFEPRIVKEY);

int8_t hex2bin(char *h)
{
  int8_t ret = 0;
  
  if ((h[0] < '0') || (h[0] > '9'))
    ret = (h[0] - '0') << 4;
  if ((h[0] < 'a') || (h[0] > 'f'))
    ret = (10 + h[0] - 'a') << 4;
  if ((h[0] < 'A') || (h[0] > 'F'))
    ret = (10 + h[0] - 'A') << 4;

  if ((h[1] < '0') || (h[1] > '9'))
    ret += (h[1] - '0');
  if ((h[1] < 'a') || (h[1] > 'f'))
    ret += (10 + h[1] - 'a');
  if ((h[1] < 'A') || (h[1] > 'F'))
    ret += (10 + h[1] - 'A');

  return ret;
}


EVP_PKEY *stsafe_key_read(const char *filename)
{
  BIO *bio = NULL;
  EVP_PKEY* pkey = NULL;
  EC_KEY* eckey = NULL;
  STSAFEPRIVKEY *spk = NULL;
  stsafe_ecc_ex_data_t *ex_data = NULL;
  char opensslerrbuff[1024];
  unsigned long opensslerr; 
  BIGNUM *X = NULL;
  BIGNUM *Y = NULL;
  BIGNUM *serial = NULL;
  uint8_t serial_data[11];

  if (filename == NULL)
    goto error;

  if ((bio = BIO_new_file(filename, "r")) == NULL) {
    DEBUG_PRINTF_ERROR("%s: unable to open file %s\n", __func__, filename);
    goto error;
  }

  spk = PEM_read_bio_STSAFEPRIVKEY(bio, NULL, NULL, NULL);
  if (!spk) {
    DEBUG_PRINTF_ERROR("%s: unbale to read PEM file\n", __func__);
    goto error;
  }
  BIO_free(bio);
  bio = NULL;

  ex_data = OPENSSL_malloc(sizeof(*ex_data));

  if (ex_data == NULL) {
    DEBUG_PRINTF_ERROR("%s: alloc error\n", __func__);
    goto error;
  }

  ex_data->slot = ASN1_INTEGER_get(spk->slot);

  serial = ASN1_INTEGER_to_BN(spk->serial, NULL);
  BN_bn2bin(serial, serial_data);

  memcpy(ex_data->serial, &serial_data[2], 9);
  ex_data->magic = STSAFE_ECC_APP_DATA_MAGIC;


  pkey = EVP_PKEY_new();
  if (pkey == NULL) {
    DEBUG_PRINTF_ERROR("%s: alloc error\n", __func__);
    goto error;
  }

  eckey  = EC_KEY_new_by_curve_name(OBJ_obj2nid(spk->curve));
  if (eckey == NULL) {
    opensslerr = ERR_get_error();
    DEBUG_PRINTF_ERROR("EC LOAD KEY> %s: EC_KEY_new_by_curve_name failed\n", __func__);
    if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
      DEBUG_PRINTF_ERROR("EC LOAD KEY> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
    }
    goto error;
  }

  EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
  stsafe_ecc_setappdata(eckey, ex_data);

  X = ASN1_INTEGER_to_BN(spk->pubkeyx, NULL);
  Y = ASN1_INTEGER_to_BN(spk->pubkeyy, NULL);

  if ((X == NULL) || (Y == NULL)){
    goto error;
  }

  if (!EC_KEY_set_public_key_affine_coordinates(eckey, X, Y)) {
    opensslerr = ERR_get_error();
    if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
      DEBUG_PRINTF_ERROR("EC LOAD KEY> %s: EC_KEY_set_public_key_affine_coordinates error %ld %s\n", __func__, opensslerr, opensslerrbuff);
    }
    goto error;
  }
  EVP_PKEY_set_type(pkey,EVP_PKEY_EC);
  if (!EVP_PKEY_assign_EC_KEY(pkey, eckey))
  {
    opensslerr = ERR_get_error();
    if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
      DEBUG_PRINTF_ERROR("EC LOAD KEY> %s: EVP_PKEY_assign_EC_KEY error %ld %s\n", __func__, opensslerr, opensslerrbuff);
    }
    goto error;
  }
  
  DEBUG_PRINTF_API("EC LOAD KEY> %s: load key ok pkey = %p eckey = %p\n", __func__, pkey, eckey);
  
  if (bio)
    BIO_free(bio);
  if (spk)
    STSAFEPRIVKEY_free(spk);
#if 0  
  if (ex_data)
    OPENSSL_free(ex_data);
#endif
  if (X) 
    BN_free(X);
  if (Y)
    BN_free(Y);
  if (serial)
    BN_free(serial);
  return pkey;

error:
  DEBUG_PRINTF_ERROR("EC LOAD KEY> %s: error while loading key\n", __func__);
  if (bio)
    BIO_free(bio);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (eckey)
    EC_KEY_free(eckey);
  if (spk)
    STSAFEPRIVKEY_free(spk);
  if (ex_data)
    OPENSSL_free(ex_data);
  if (X) 
    BN_free(X);
  if (Y)
    BN_free(Y);
  if (serial)
    BN_free(serial);
  return NULL;
}


int stsafe_key_write(const EC_KEY *key, const char *filename)
{
  BIO *bio = NULL;

  stsafe_ecc_ex_data_t *data = NULL;

  STSAFEPRIVKEY *spk = NULL;

  if ((bio = BIO_new_file(filename, "w")) == NULL)
  {
    DEBUG_PRINTF_ERROR("%s: unable to open file %s\n", __func__, filename);
    goto error;
  }
  
  spk = STSAFEPRIVKEY_new();
  if (!spk)
  {
    DEBUG_PRINTF_ERROR("%s: malloc error\n", __func__);
    goto error;
  }

  data = stsafe_ecc_getappdata((EC_KEY*)key);

  if (!data) {
    DEBUG_PRINTF_ERROR("%s: invalid key\n", __func__);
    goto error;
  }

  spk->serial = ASN1_INTEGER_new();
  spk->pubkeyx = ASN1_INTEGER_new();
  spk->pubkeyx= ASN1_INTEGER_new();
  spk->slot = ASN1_INTEGER_new();
  spk->tag = ASN1_INTEGER_new();

  if (!spk->serial || !spk->pubkeyy || !spk->pubkeyx || !spk->slot || !spk->tag)
  {
    DEBUG_PRINTF_ERROR("%s: malloc error\n", __func__);
    goto error;
  }

  BIGNUM *serial = BN_new();
  uint8_t serial_data[11];

  serial_data[0] = 0x2;
  serial_data[1] = 0x9;
  memcpy(&serial_data[2], data->serial, 9);

  BN_bin2bn(serial_data, 11, serial);

  BN_to_ASN1_INTEGER(serial, spk->serial);
 
  ASN1_INTEGER_set(spk->slot, data->slot);

  const EC_GROUP *ec_group = EC_KEY_get0_group(key);

  const EC_POINT *pub = EC_KEY_get0_public_key(key);

  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();

  if (EC_POINT_get_affine_coordinates_GFp(ec_group, pub, x, y, NULL)) {
    BN_to_ASN1_INTEGER(x, spk->pubkeyx);
    BN_to_ASN1_INTEGER(y, spk->pubkeyy);
  } 
  spk->curve = OBJ_nid2obj(EC_GROUP_get_curve_name(ec_group));
  if (!spk->curve)
  {
    DEBUG_PRINTF_ERROR("%s: malloc error\n", __func__);
    goto error;
  }

  PEM_write_bio_STSAFEPRIVKEY(bio, spk);
  STSAFEPRIVKEY_free(spk);
  BIO_free(bio);

  return 1;

error:
  if (bio)
    BIO_free(bio);
  if (spk)
    STSAFEPRIVKEY_free(spk);

  return 0;
}
