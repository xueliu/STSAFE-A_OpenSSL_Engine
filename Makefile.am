INCLUDE_DIRS = -I$(srcdir)/inc -I$(srcdir)/lib/STSAFE_Axx0/CoreModules/Inc
ACLOCAL_AMFLAGS = -I m4 --install
AM_CFLAGS  = $(INCLUDE_DIRS) $(EXTRA_CFLAGS) $(CRYPTO_CFLAGS)
AM_LDFLAGS = $(EXTRA_LDFLAGS)
AM_LDADD = $(CRYPTO_LIBS) 

if DEBUG
AM_CFLAGS += -DDEBUG
AM_CFLAGS += -DDEBUG_LEVEL=$(DEBUG_LEVEL)
endif

if STSAFE_NO_ECDSA_VERIFY
AM_CFLAGS += -DSTSAFE_ECDSA_VERIFY=0
else
AM_CFLAGS += -DSTSAFE_ECDSA_VERIFY=1
endif

if STSAFE_NO_ECDH
AM_CFLAGS += -DSTSAFE_ECDH_ENABLE=0
else
AM_CFLAGS += -DSTSAFE_ECDH_ENABLE=1
endif

if STSAFE_A100
AM_CFLAGS += -DSTSAFE_A100
else !STSAFE_A100
AM_CFLAGS += -DSTSAFE_A110
endif !STSAFE_A100

EXTRA_DIST =

if HAS_I2C_ADDR
AM_CFLAGS += -DSTSAFEA_DEVICE_ADDRESS=$(I2C_ADDR) 
endif

if HAS_I2C_BUS
AM_CFLAGS += -DSTSAFEA_DEFAULT_I2CBUS=\"$(I2C_BUS)\" 
endif

openssl_enginedir = $(ENGINESDIR)
openssl_engine_LTLIBRARIES = libStsafe.la

include_HEADERS = inc/ec_local.h \
                  inc/engine_debug.h \
                  inc/refcount.h \
                  inc/stsafea_conf.h \
                  inc/stsafe_a_configuration.h \
                  inc/stsafea_interface_conf.h \
                  inc/stsafe_api.h \
                  inc/stsafe_init.h \
                  lib/STSAFE_Axx0/CoreModules/Inc/stsafea100.h \
                  lib/STSAFE_Axx0/CoreModules/Inc/stsafea_service.h \
                  lib/STSAFE_Axx0/CoreModules/Inc/stsafea110.h \
                  lib/STSAFE_Axx0/CoreModules/Inc/stsafea_types.h \
                  lib/STSAFE_Axx0/CoreModules/Inc/stsafea_core.h  \
                  lib/STSAFE_Axx0/CoreModules/Inc/stsafeaxxx.h \
                  lib/STSAFE_Axx0/CoreModules/Inc/stsafea_crypto.h 

libStsafe_la_SOURCES = src/engine_init.c \
                       src/stsafea_service_interface_engine.c \
                       src/stsafe_cmd.c \
                       src/stsafe_ecdsa.c \
                       src/stsafe_pem_priv.c \
                       src/stsafe_rand.c \
                       src/stsafea_crypto_openssl_interface_engine.c \
                       src/stsafe_cipher.c \
                       src/stsafe_configuration.c \
                       src/stsafe_init.c \
                       src/stsafe_pkey_meth.c \
                       src/stsafe_zone.c \
                       lib/STSAFE_Axx0/CoreModules/Src/stsafea_core.c \
                       lib/STSAFE_Axx0/CoreModules/Src/stsafea_service.c \
                       lib/STSAFE_Axx0/CoreModules/Src/stsafea_crypto.c


libStsafe_la_CFLAGS = $(AM_CFLAGS)
libStsafe_la_LIBADD = $(AM_LDADD)
libStsafe_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version 

install-exec-local:
	([ -e $(DESTDIR)$(openssl_enginedir) ] || $(MKDIR_P) $(DESTDIR)$(openssl_enginedir))


install-exec-hook:
	(cd $(DESTDIR)$(openssl_enginedir) && $(LN_S) -f libStsafe.so Stsafe.so)

uninstall-hook:
	(cd $(DESDIR)$(openssl_enginedir) && [ -L Stsafe.so ] && rm -f Stsafe.so )

bin_PROGRAMS = stsafe_genkey

stsafe_genkey_SOURCES = Examples/stsafe_genkey/src/stsafe_genkey.c
stsafe_genkey_CFLAGS = $(AM_CFLAGS)
stsafe_genkey_LDADD = $(AM_LDADD) libStsafe.la
stsafe_genkey_LDFLAGS = $(AM_LDFLAGS)


bin_PROGRAMS += stsafe_engine_test_suite

stsafe_engine_test_suite_SOURCES = Examples/stsafe_engine_test_suite/ecdh_test.c \
                                   Examples/stsafe_engine_test_suite/query_test.c \
                                   Examples/stsafe_engine_test_suite/ecdsa_sign_verify.c \
                                   Examples/stsafe_engine_test_suite/rand_test.c \
                                   Examples/stsafe_engine_test_suite/pkey_test.c \
                                   Examples/stsafe_engine_test_suite/test_stsafe_engine.c
stsafe_engine_test_suite_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/Examples/stsafe_engine_test_suite/inc
stsafe_engine_test_suite_LDADD = $(AM_LDADD) libStsafe.la
stsafe_engine_test_suite_LDFLAGS = $(AM_LDFLAGS)

