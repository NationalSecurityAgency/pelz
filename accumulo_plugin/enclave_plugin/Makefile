#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_SSL_UNTRUSTED_LIB_PATH ?= /opt/intel/sgxssl/lib64/
SGX_SSL_TRUSTED_LIB_PATH ?= /opt/intel/sgxssl/lib64/
SGX_SSL_INCLUDE_PATH ?= /opt/intel/sgxssl/include/


ENCLAVE_HEADER_TRUSTED ?= '"acummulo_enclave_t.h"'
ENCLAVE_HEADER_UNTRUSTED ?= '"acummulo_enclave_u.h"'


ifeq ($(shell getconf LONG_BIT), 32)
  SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
  SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
  SGX_COMMON_FLAGS := -m32
  SGX_LIBRARY_PATH := $(SGX_SDK)/lib
  SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
  SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
  SGX_COMMON_FLAGS := -m64
  SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
  SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
  SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
  SGX_COMMON_FLAGS += -O0 -g
else
  SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wextra
SGX_COMMON_FLAGS += -Winit-self
SGX_COMMON_FLAGS += -Wpointer-arith
SGX_COMMON_FLAGS += -Wreturn-type
SGX_COMMON_FLAGS += -Waddress
SGX_COMMON_FLAGS += -Wsequence-point
SGX_COMMON_FLAGS += -Wformat-security
SGX_COMMON_FLAGS += -Wmissing-include-dirs
SGX_COMMON_FLAGS += -Wfloat-equal
SGX_COMMON_FLAGS += -Wundef
SGX_COMMON_FLAGS += -Wshadow
SGX_COMMON_FLAGS += -Wcast-align
SGX_COMMON_FLAGS += -Wcast-qual
#SGX_COMMON_FLAGS += -Wconversion
SGX_COMMON_FLAGS += -Wredundant-decls

SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS)
SGX_COMMON_CFLAGS += -Wstrict-prototypes
SGX_COMMON_CFLAGS += -Wunsuffixed-float-constants
SGX_COMMON_CFLAGS += -Wjump-misses-init

SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS)
SGX_COMMON_CXXFLAGS += -Wnon-virtual-dtor 

######## App Settings ########

ifneq ($(SGX_MODE), HW)
  Urts_Library_Name := sgx_urts_sim
else
  Urts_Library_Name := sgx_urts
endif

App_File := untrusted/accumulo_enclave.c 

App_C_Files := ../../src/util/charbuf.c \
				untrusted/src/interface.c \
				untrusted/src/file_enc_dec.c

App_Include_Paths := -I../../include
App_Include_Paths += -I../../include/cipher
App_Include_Paths += -I$(SGX_SDK)/include 
App_Include_Paths += -Iuntrusted/include
App_Include_Paths += -Itrusted/include
App_Include_Paths += -Itrusted
App_Include_Paths += -I../../kmyth/sgx/untrusted/include/ocall

App_C_Flags := $(SGX_COMMON_CFLAGS) 
App_C_Flags += -fPIC 
App_C_Flags += -Wno-attributes 
App_C_Flags += $(App_Include_Paths) 
App_C_Flags += -DACCUMULO_SGX_UNTRUSTED
App_C_Flags += -Wall

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
		App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
		App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
		App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(SGX_COMMON_CXXFLAGS)
App_Cpp_Flags += $(App_Include_Paths)
App_Cpp_Flags += -std=c++11 
App_Cpp_Flags += -DACCUMULO_SGX_UNTRUSTED

App_Link_Flags := -L$(SGX_SSL_UNTRUSTED_LIB_PATH) 
App_Link_Flags += -L$(SGX_LIBRARY_PATH) 
App_Link_Flags += -l$(Urts_Library_Name) 
App_Link_Flags += -lsgx_usgxssl 
App_Link_Flags += -lkmyth-logger 
App_Link_Flags += -lkmyth-utils 
App_Link_Flags += -lkmip
App_Link_Flags += -lpthread 

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Name := accumulo-enclave

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Include_Paths := -I../../include
Enclave_Include_Paths += -I../../include/cipher
Enclave_Include_Paths += -I$(SGX_SDK)/include 
Enclave_Include_Paths += -I$(SGX_SDK)/include/tlibc
Enclave_Include_Paths += -I$(SGX_SSL_INCLUDE_PATH) 
Enclave_Include_Paths += -I/usr/local/include
Enclave_Include_Paths += -Itrusted
Enclave_Include_Paths += -Itrusted/include
Enclave_Include_Paths += -Iuntrusted/include
Enclave_Include_Paths += -I../../kmyth/sgx/untrusted/include/ocall

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) 
Enclave_C_Flags += -fPIC
Enclave_C_Flags += -Wno-attributes
Enclave_C_Flags += -nostdinc 
Enclave_C_Flags += -fvisibility=hidden 
Enclave_C_Flags += -fpie 
Enclave_C_Flags += -fstack-protector 
Enclave_C_Flags += $(Enclave_Include_Paths) 
Enclave_C_Flags += -DACCUMULO_SGX_TRUSTED
Enclave_C_Flags += -Wall 

Enclave_Cpp_Flags := $(SGX_COMMON_CXXFLAGS)
Enclave_Cpp_Flags += -fpie
Enclave_Cpp_Flags += -std=c++03 
Enclave_Cpp_Flags += -std=c++11
Enclave_Cpp_Flags += -nostdinc++ 
Enclave_Cpp_Flags += --include "tsgxsslio.h" 
Enclave_Cpp_Flags += $(Enclave_Include_Paths)
Enclave_Cpp_Flags += -DACCUMULO_SGX_TRUSTED

Enclave_Link_Flags := -Wl,--no-undefined 
Enclave_Link_Flags += -nostdlib 
Enclave_Link_Flags += -nodefaultlibs 
Enclave_Link_Flags += -nostartfiles 
Enclave_Link_Flags += -L$(SGX_SSL_TRUSTED_LIB_PATH) 
Enclave_Link_Flags += -L$(SGX_LIBRARY_PATH)
Enclave_Link_Flags += -Wl,--whole-archive -lsgx_tsgxssl
Enclave_Link_Flags += -Wl,--no-whole-archive -lsgx_tsgxssl_crypto
Enclave_Link_Flags += -Wl,--whole-archive -l$(Trts_Library_Name) 
Enclave_Link_Flags += -Wl,--no-whole-archive 
Enclave_Link_Flags += -Wl,--start-group 
Enclave_Link_Flags += -lsgx_tstdc 
Enclave_Link_Flags += -lsgx_tcxx 
Enclave_Link_Flags += -lsgx_pthread 
Enclave_Link_Flags += -l$(Crypto_Library_Name) 
Enclave_Link_Flags += -l$(Service_Library_Name) 
Enclave_Link_Flags += -Wl,--end-group
Enclave_Link_Flags += -Wl,-Bstatic 
Enclave_Link_Flags += -Wl,-Bsymbolic 
Enclave_Link_Flags += -Wl,--no-undefined 
Enclave_Link_Flags += -Wl,-pie,-eenclave_entry 
Enclave_Link_Flags += -Wl,--export-dynamic
Enclave_Link_Flags += -Wl,--defsym,__ImageBase=0
Enclave_Link_Flags += -lkmip-sgx

Enclave_Name := accumulo_enclave.so
Enclave_Signing_Key := accumulo_enclave_private.pem
Signed_Enclave_Name := accumulo_enclave.signed.so
Enclave_Config_File := trusted/accumulo_enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

# Message for missing Enclave Signing Key - Fatal Build Error
define err_no_enclave_signing_key
FAIL - No Enclave Signing Key found
Generate or install trusted/$(Enclave_Signing_Key)
e.g., run 'openssl genrsa -out trusted/$(Enclave_Signing_Key) -3 3072'
endef


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: override ENCLAVE_HEADERS = -DENCLAVE_HEADER_TRUSTED=$(ENCLAVE_HEADER_TRUSTED) -DENCLAVE_HEADER_UNTRUSTED=$(ENCLAVE_HEADER_UNTRUSTED)
all: pre bin/$(App_Name) trusted/$(Signed_Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else			
all: override ENCLAVE_HEADERS = -DENCLAVE_HEADER_TRUSTED=$(ENCLAVE_HEADER_TRUSTED) -DENCLAVE_HEADER_UNTRUSTED=$(ENCLAVE_HEADER_UNTRUSTED)	
all: pre bin/$(App_Name) trusted/$(Signed_Enclave_Name)
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

trusted/log_ocall.o: ../../kmyth/sgx/untrusted/src/ocall/log_ocall.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

trusted/memory_ocall.o: ../../kmyth/sgx/untrusted/src/ocall/memory_ocall.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

trusted/accumulo_enclave_u.c: $(SGX_EDGER8R) trusted/accumulo_enclave.edl
	@cd trusted && $(SGX_EDGER8R) --untrusted accumulo_enclave.edl \
				  --search-path . \
					--search-path include \
				  --search-path $(SGX_SDK)/include \
				  --search-path $(SGX_SSL_INCLUDE_PATH) \
					--search-path ../untrusted/include \
				  --search-path ../../../include 
	@echo "GEN  =>  $@"

trusted/accumulo_enclave_u.o: trusted/accumulo_enclave_u.c
	@$(CC) $(App_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

bin/$(App_Name): $(App_File) \
		      $(App_C_Files) \
		      trusted/accumulo_enclave_u.o \
		      trusted/log_ocall.o \
				  trusted/memory_ocall.o
	@$(CC) $^ -o $@ $(App_C_Flags) \
			 $(App_Include_Paths) \
			 -Itrusted \
			 $(App_C_Flags) \
			 $(ENCLAVE_HEADERS) \
			 $(App_Link_Flags) \
			 -Lsgx \
			 -lcrypto
	@echo "LINK =>  $(App_Name)"

######## Enclave Objects ########

trusted/accumulo_enclave_t.c: $(SGX_EDGER8R) trusted/accumulo_enclave.edl
	@cd trusted && $(SGX_EDGER8R) --trusted accumulo_enclave.edl \
				  --search-path . \
					--search-path include \
				  --search-path $(SGX_SDK)/include \
				  --search-path $(SGX_SSL_INCLUDE_PATH) \
					--search-path ../untrusted/include \
					--search-path ../../../include
	@echo "GEN => $@"

trusted/accumulo_enclave_t.o: trusted/accumulo_enclave_t.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

trusted/file_encrypt_decrypt.o: trusted/src/file_encrypt_decrypt.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

trusted/pelz_aes_gcm.o: ../../src/cipher/pelz_aes_gcm.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

trusted/memory_util.o: ../../kmyth/utils/src/memory_util.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

trusted/pelz_aes_keywrap_3394nopad.o: ../../src/cipher/pelz_aes_keywrap_3394nopad.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

trusted/charbuf.o: ../../src/util/charbuf.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

trusted/pelz_cipher.o: ../../src/cipher/pelz_cipher.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

trusted/$(Enclave_Name): trusted/accumulo_enclave_t.o \
		     trusted/file_encrypt_decrypt.o \
		     trusted/pelz_aes_keywrap_3394nopad.o \
		     trusted/charbuf.o \
		     trusted/pelz_aes_gcm.o \
		     trusted/memory_util.o \
		     trusted/pelz_cipher.o \
		     trusted/enclave_request_signing.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags) $(ENCLAVE_HEADERS)
	@echo "LINK =>  $@"

trusted/$(Enclave_Signing_Key):
	$(error $(err_no_enclave_signing_key))

trusted/$(Signed_Enclave_Name): trusted/$(Enclave_Name) trusted/$(Enclave_Signing_Key)
	@$(SGX_ENCLAVE_SIGNER) sign -key trusted/$(Enclave_Signing_Key) \
				    -enclave trusted/$(Enclave_Name) \
				    -out $@ \
				    -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: pre

pre:
	@mkdir -p bin
	@mkdir -p log

.PHONY: clean

clean:
	@rm -r bin
	@rm -r log
	@rm -f trusted/*.so
	@rm -f trusted/*_u.*
	@rm -f trusted/*_t.*
	@rm -f trusted/*.o
