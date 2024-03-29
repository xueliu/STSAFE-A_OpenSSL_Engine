/**
 *********************************************************************************************
 * @file    stsafe_genkey.c
 * @author  SMD application team
 * @version V1.0.0
 * @date    31-July-2020
 * @brief   Openssl STSAFE Engine EC key generation tool
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

#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <unistd.h>
#include <getopt.h>

#include <openssl/engine.h>
#include <openssl/pem.h>

#include "stsafea_types.h"
#include "stsafe_api.h"
#include "stsafe_init.h"
#include "stsafea110.h"

#undef ERR
#define VERB(...) if (opt.verbose) fprintf(stderr, __VA_ARGS__)
#define ERR(...) fprintf(stderr, __VA_ARGS__)

int debug_level = 4;

char *help =
    "Usage: [options] <filename>\n"
    "Arguments:\n"
    "    <filename>      storage for the public key\n"
    "Options:\n"
    "    -c, --curve     curve for ecc (default: nist_p256)\n"
    "    -h, --help      print help\n"
    "    -s, --slot      slot to use for key generation (default slot0)\n"
    "    -v, --verbose   print verbose messages\n"
    "\n";

static const char *optstr = "c:hs:v";

static const struct option long_options[] = {
    {"curve",    required_argument, 0, 'c'},
    {"help",     no_argument,       0, 'h'},
    {"slot",     required_argument, 0, 's'},
    {"verbose",  no_argument,       0, 'v'},
    {0,          0,                 0,  0 }
};

static struct opt {
    char             *filename;
    StSafeA_CurveId_t curve;
    uint8_t           slot;
    int               verbose;
} opt;

/**
 *
 * @brief This function parses the command line options and sets the appropriate values
 * in the opt struct.
 * @param argc The argument count.
 * @param argv The arguments.
 * @retval EXIT_SUCCESS on success
 * @retval EXIT_FAILURE on failure
 */
int
parse_opts(int argc, char **argv)
{
    /* set the default values */
    opt.filename = NULL;
    opt.curve    = STSAFEA_NIST_P_256;
    opt.slot     = STSAFEA_KEY_SLOT_0;
    opt.verbose  = 0;

    /* parse the options */
    int c;
    int opt_idx = 0;
    while (-1 != (c = getopt_long(argc, argv, optstr,
                                  long_options, &opt_idx))) {
        switch(c) {
        case 'h':
            fprintf(stdout, "%s", help);
            exit(EXIT_SUCCESS);
        case 'v':
            opt.verbose = 1;
            break;
        case 'c':
            if (strcasecmp(optarg, "nist_p256") == 0) {
                opt.curve = STSAFEA_NIST_P_256;
                break;
            } else if (strcasecmp(optarg, "nist_p384") == 0) {
                opt.curve = STSAFEA_NIST_P_384;
                break;
            } else if (strcasecmp(optarg, "brainpool_p256") == 0) {
                opt.curve = STSAFEA_BRAINPOOL_P_256;
                break;
            } else if (strcasecmp(optarg, "brainpool_p384") == 0) {
                opt.curve = STSAFEA_BRAINPOOL_P_384;
                break;
            } else {
                ERR("Unknown curve.\n");
                exit(EXIT_FAILURE);
            }
        case 's':
        {
            int err = 1;
            sscanf(optarg, "%i", (int *)&opt.slot);
            if ( (opt.slot == STSAFEA_KEY_SLOT_0) ||
                 (opt.slot == STSAFEA_KEY_SLOT_1)
#if STSAFE_ECDH_ENABLE
		 || (opt.slot == STSAFEA_KEY_SLOT_EPHEMERAL)
#endif
	       ) {

                 err = 0;
            }
            if (err) {
                ERR("Error parsing slot. %i\n", opt.slot);
                exit(EXIT_FAILURE);
            }
            break;
        }
        default:
            ERR("Unknown option at index %i.\n\n", opt_idx);
            ERR("%s", help);
            exit(EXIT_FAILURE);
        }
    }

    /* parse the non-option arguments */
    if (optind >= argc) {
        ERR("Missing argument <filename>.\n\n");
        ERR("%s", help);
        exit(EXIT_FAILURE);
    }
    opt.filename = argv[optind];
    optind++;

    if (optind < argc) {
        ERR("Unknown argument provided.\n\n");
        ERR("%s", help);
        exit(EXIT_FAILURE);
    }
    return 0;
}

/**
 * @brief This function initializes the STSAFE OpenSSL engine and calls
 * the key generation functions.
 * @param argc The command line argument count
 * @param argv The command line arguments
 * @return EXIT_SUCCESS on success
 * @return EXIT_FAILURE on failure
 */
int
main(int argc, char **argv)
{
    char                   opensslerrbuff[1024];

    unsigned long          opensslerr    = 0;
    int                    nid           = -1;
    EC_KEY                *myecc         = NULL;
    EVP_PKEY              *pkey          = NULL;
    ENGINE                *stsafe_engine = NULL;
    OPENSSL_INIT_SETTINGS *settings      = NULL;

    memset(opensslerrbuff, 0x00, 1024 * sizeof(char));

    if (parse_opts(argc, argv) != 0) {
        exit(EXIT_FAILURE);
    }

    settings = OPENSSL_INIT_new();
    if (settings == NULL) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: OPENSSL_INIT_new failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        exit(EXIT_FAILURE);
    }

    if (OPENSSL_INIT_set_config_filename(settings, "./openssl.conf.stsafe") == 0) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: OPENSSL_INIT_set_config_filename failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        exit(EXIT_FAILURE);
    };

    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, settings) == 0) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: OPENSSL_init_crypto failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        exit(EXIT_FAILURE);
    }

    // Load the engine
    stsafe_engine = ENGINE_by_id("Stsafe");
    if (stsafe_engine == NULL) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: ENGINE_by_id failed to load\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        exit(EXIT_FAILURE);
    }

    // Initialize STSAFE ENGINE
    if (! ENGINE_init(stsafe_engine)) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: ENGINE_init failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }

    // Set Stsafe as default for Eliptic Curve (EC)
    if (! ENGINE_set_default_EC(stsafe_engine)) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: ENGINE_set_default_EC failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }

    // Set the slot
    if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_SET_GEN_KEY_SLOT, opt.slot, NULL, NULL)) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: ENGINE_ctrl could not slet Slot %d failed\n", __func__, opt.slot);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }
#if 0
    // get Serial;

    if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_GET_SERIAL_NUMBER, 0, data.serial, NULL)) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: ENGINE_ctrl could not get serial number failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }
#endif
    // Set the slot
    if (!ENGINE_ctrl(stsafe_engine, STSAFE_CMD_SET_GEN_KEY_SLOT, opt.slot, NULL, NULL)) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: ENGINE_ctrl could not slet Slot %d failed\n", __func__, opt.slot);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }
    // Generate the key
    VERB("STSAFEKEYGEN> %s: Generating the key\n", __func__);

    // Setup the EC structure
    switch(opt.curve) {
    case STSAFEA_NIST_P_256:
        nid = NID_X9_62_prime256v1;
        break;
    case STSAFEA_NIST_P_384:
        nid = NID_secp384r1;
        break;
    case STSAFEA_BRAINPOOL_P_256:
        nid = NID_brainpoolP256r1;
        break;
    case STSAFEA_BRAINPOOL_P_384:
        nid = NID_brainpoolP384r1;
        break;
    }

    VERB("STSAFEKEYGEN> %s: nid = %d\n", __func__, nid);

    myecc  = EC_KEY_new_by_curve_name(nid);
    if (myecc == NULL) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: EC_KEY_new_by_curve_name failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }

    EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

    if (! (EC_KEY_generate_key(myecc))) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: EC_KEY_generate_key failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }

#if 0
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: EVP_PKEY_new failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }

    if (! EVP_PKEY_assign_EC_KEY(pkey, myecc)) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: EVP_PKEY_assign_EC_KEY failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        EVP_PKEY_free(pkey);
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }
    // Write to file
    VERB("STSAFEKEYGEN> %s: Writing Public Key to %s\n", __func__, opt.filename);
    outbio = BIO_new_file(opt.filename, "w");
    if (outbio == NULL) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: BIO_new_file failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        EVP_PKEY_free(pkey);
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }

    if (! PEM_write_bio_PUBKEY(outbio, pkey)) {
        opensslerr = ERR_get_error();
        ERR("STSAFEKEYGEN> %s: PEM_write_bio_PUBKEY failed\n", __func__);
        if (ERR_error_string(opensslerr, opensslerrbuff) != NULL) {
            ERR("STSAFEKEYGEN> %s: OpenSSL error %ld %s\n", __func__, opensslerr, opensslerrbuff);
        }
        EVP_PKEY_free(pkey);
        ENGINE_free(stsafe_engine);
        exit(EXIT_FAILURE);
    }
#else

    stsafe_key_write(myecc, opt.filename);
#endif
    // tidy up
    EVP_PKEY_free(pkey);

    exit(EXIT_SUCCESS);
}
