####################################################################
#                                                                 ##
# Copyright (c) STMicroelectronics Inc. 2020                      ##
#                                                                 ##
# STSAFE-A110 Makefile common include file                        ##
#                                                                 ##
####################################################################

# Tools
CC  ?= gcc -c
CPP ?= gcc
LD  := gcc
CP  ?= cp

# Tool flags
CCWARNFLAGS   = -Wall -W
CCOPTFLAGS    = -O2
CCEXTRAFLAGS  =
CCDEBUGFLAGS  = -O0 -g
CFLAGS        = -c $(CCDEBUGFLAGS) $(CCWARNFLAGS) $(CCEXTRAFLAGS)
LDFLAGS       = -L $(OPENSSL_LIB) 
LDLIBS        = -lcrypto
DEPENDS_FLAGS = $(CFLAGS) $(INCLS)

# Dependancy creation command
MAKEDEPENDCMD = $(CPP) $(DEPENDS_FLAGS) -M

# Openssl directory setup
OPENSSL_INC = /opt/openssl/include
OPENSSL_LIB = /opt/openssl/lib
OPENSSL_BIN = /opt/openssl/bin

# Include path setup, we always default to /opt/openssl
ifeq ($(OPENSSL_INC),)
ifneq (,$(wildcard  /opt/openssl))
	OPENSSL_INC = /opt/openssl/include
	OPENSSL_LIB = /opt/openssl/lib
	OPENSSL_BIN = /opt/openssl/bin
else ifneq (,$(wildcard /usr/include/openssl))
	OPENSSL_INC = /usr/include/openssl
	OPENSSL_LIB = /usr/lib
	OPENSSL_BIN = /usr/bin
else
	result := $(error OPENSSL library not found in either /usr or /opt please edit file with correct location)
	OPENSSL_INC =
	OPENSSL_LIB =
	OPENSSL_BIN =
endif
endif

INCLS = -I ${BUILD_ROOT}/inc \
        -I ${BUILD_ROOT}/lib/STSAFE_Axx0/CoreModules/Inc \
        -I ${BUILD_ROOT}/lib/STSAFE_Axx0/Interface \
		-I ${BUILD_ROOT}/lib/OpenSSL/Inc  \
		-I ${OPENSSL_INC} \
		-I $(SRC_DIR)/inc

# Rule .o from .c
%.o :  %.c; echo 'Compiling $<'; $(CC) $(CFLAGS) $(INCLS) $< -o $@;
