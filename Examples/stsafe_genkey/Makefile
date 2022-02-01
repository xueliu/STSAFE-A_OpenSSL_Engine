####################################################################
#                                                                 ##
# Copyright (c) STMicroelectronics Inc. 2020                      ##
#                                                                 ##
# STSAFE-A110 stsafe_genkey Makefile                              ##
#                                                                 ##
####################################################################

# All makefiles share a common include file
include ../../make.inc

# Setup directories
BUILD_ROOT = ../..
SRC_DIR    = src
BIN_DIR    = bin

# Build specific flags
# None for this build

# Target name.
BIN     = stsafe_genkey

# Create src/objs
SRCS  =	$(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst %.c,%.o,$(SRCS))

all: $(BIN)

$(BIN) : $(OBJS)
	 @echo ---- Building $(BIN) using OpenSSL from $(OPENSSL_INC) ----
	 $(LD) $(LDFLAGS) $(LDLIBS) $(OBJS) -o $(BIN_DIR)/$@ -Wl,-Map=$@.map

install:
	@echo ---- Installing $(BIN) into $(OPENSSL_BIN)
	cp $(BINDIR)/$@ $(OPENSSL_BIN)/.

.PHONY: clean

clean:
	$(RM) -f $(OBJS) $(BIN) $(BIN_DIR)/$(BIN) $(DEPENDS_FILE) *.map

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
