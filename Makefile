####################################################################
#                                                                 ##
# Copyright (c) STMicroelectronics Inc. 2020                      ##
#                                                                 ##
# STSAFE-A110 stsafe library Makefile                             ##
#                                                                 ##
####################################################################

# All makefiles share a common include file
include make.inc

# Setup directories
BUILD_ROOT = $(shell pwd)
SRC_DIR    = $(BUILD_ROOT)/src

# Build specific flags
CCEXTRAFLAGS += -fPIC -DSTSAFE_A110 -DBUS_CONF_DEBUG
LDFLAGS      += 
LDLIBS       += -lssl

# Target name
LIBNAME = libStsafe.so
LIB     = Stsafe.so

# Create src/objs
SRCS  = $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst %.c,%.o,$(SRCS))

CORE_SRCS  = $(wildcard $(BUILD_ROOT)/lib/STSAFE_Axx0/CoreModules/Src/*.c)
CORE_OBJS := $(patsubst %.c,%.o,$(CORE_SRCS))

IF_OBJS := $(patsubst %.c,%.o,$(IF_SRCS))

all: $(LIB)

$(LIB) : $(OBJS) $(CORE_OBJS) $(IF_OBJS)
	@echo ---- Building $(LIB) using OpenSSL from $(OPENSSL_INC) ----
	$(LD) -shared -Wl,--soname=$(LIB) -o $@ $^ $(LDFLAGS) $(LDLIBS)
	$(CP) $(LIB) $(LIBNAME)
install:
	@echo ---- Installing $(LIBNAME) into ${OPENSSL_LIB}/engines-1.1/ ----
	$(CP) $(LIB) ${OPENSSL_LIB}/engines-1.1/
	$(CP) $(LIB) ${OPENSSL_LIB}/engines-1.1/$(LIBNAME)

.PHONY: clean

clean:
	$(RM) -f $(OBJS) $(IF_OBJS) $(CORE_OBJS) $(LIB) $(LIBNAME) $(DEPENDS_FILE)

DEPENDS_FILE	= dependsfile.d

ifneq ($(findstring clean, $(MAKECMDGOALS)),clean)

$(DEPENDS_FILE):
	@echo 'Creating Depends file for $(BIN)'
	$(MAKEDEPENDCMD) $(SRCS) $(CORE_SRCS) $(IF_SRCS) > $(DEPENDS_FILE)
endif


#
# This file gets created by the make depends rule it will self generate all the 
# rules to compile the individual C files.
#
-include $(DEPENDS_FILE)
