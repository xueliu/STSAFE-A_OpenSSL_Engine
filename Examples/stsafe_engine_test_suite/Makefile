####################################################################
#                                                                 ##
# Copyright (c) STMicroelectronics Inc. 2020                      ##
#                                                                 ##
# STSAFE-A110 stsafe test suite Makefile                          ##
#                                                                 ##
####################################################################

# All makefiles share a common include file
include ../../make.inc

# Setup directories
BUILD_ROOT  = ../..
SRC_DIR     = $(shell pwd)

# Build specific flags
CCEXTRAFLAGS += -fPIC
LDFLAGS      += -L$(BUILD_ROOT) $(LDLIBS) -Wl,-rpath=$(BUILD_ROOT)
LDLIBS       += -lssl -lStsafe

# Target name
BIN           = test_stsafe_engine

# Create src/objs
SRCS  = $(wildcard *.c)
OBJS := $(patsubst %.c,%.o,$(SRCS))

all: $(BIN)

$(BIN) : $(OBJS)
	 @echo ---- Building $(BIN) using OpenSSL from $(OPENSSL_INC) and STSAFE Engine $(BUILD_ROOT) ----
	 $(LD) $(LDFLAGS) $(OBJS) -o $@ -Wl,-Map=$@.map

.PHONY: clean

clean:
	$(RM) -f $(OBJS) $(BIN) $(DEPENDS_FILE) *.map

DEPENDS_FILE	= dependsfile.d

ifneq ($(findstring clean, $(MAKECMDGOALS)),clean)

$(DEPENDS_FILE):
	@echo 'Creating Depends file for $(BIN)'
	$(MAKEDEPENDCMD) $(SRCS) > $(DEPENDS_FILE)
endif


#
# This file gets created by the make depends rule it will self generate all the 
# rules to compile the individual C files.
#
-include $(DEPENDS_FILE)
