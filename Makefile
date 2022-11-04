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


TEST_ENCLAVE_HEADER_TRUSTED ?= '"test_enclave_t.h"'
TEST_ENCLAVE_HEADER_UNTRUSTED ?= '"test_enclave_u.h"'

ENCLAVE_HEADER_TRUSTED ?= '"pelz_enclave_t.h"'
ENCLAVE_HEADER_UNTRUSTED ?= '"pelz_enclave_u.h"'


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

App_Service_File := src/pelz-service/main.c

App_Pipe_File := src/pelz/main.c

App_C_Files := src/util/charbuf.c \
		 src/util/pelz_json_parser.c \
		 src/util/pelz_service.c \
		 src/util/pelz_socket.c \
		 src/util/fifo_thread.c \
		 src/util/unsecure_socket_thread.c \
		 src/util/secure_socket_thread.c \
		 src/util/secure_socket_ecdh.c \
		 src/util/key_load.c \
		 src/util/parse_pipe_message.c \
		 src/util/pipe_io.c \
		 src/util/pelz_uri_helpers.c \
		 src/util/pelz_loaders.c

App_C_Test_Files := test/src/pelz_test.c \
		 test/src/util/util_test_suite.c \
		 test/src/util/aes_keywrap_test_suite.c \
		 test/src/util/pelz_json_parser_test_suite.c \
		 test/src/util/test_helper_functions.c \
		 test/src/util/test_pelz_uri_helpers.c \
		 test/src/util/table_test_suite.c \
		 test/src/util/request_test_suite.c \
		 test/src/util/cmd_interface_test_suite.c \
		 test/src/util/request_test_helpers.c \
		 test/src/util/test_seal.c

App_C_Files_for_Test := src/util/common_table.c \
		 src/util/key_table.c \
		 src/util/server_table.c \
		 src/cipher/pelz_aes_keywrap_3394nopad.c \
		 src/util/pelz_request_handler.c

App_C_Kmyth_Files := kmyth/sgx/untrusted/src/wrapper/sgx_seal_unseal_impl.c

App_Include_Paths := -Iinclude 
App_Include_Paths += -Isgx 
App_Include_Paths += -I$(SGX_SDK)/include 
App_Include_Paths += -Ikmyth/sgx/untrusted/include/wrapper
App_Include_Paths += -Ikmyth/sgx/untrusted/include/ocall
App_Include_Paths += -Ikmyth/sgx/common/include
App_Include_Paths += -Ikmyth/include/network
App_Include_Paths += -Ikmyth/include/protocol
App_Include_Paths += -Itest/include

App_C_Flags := $(SGX_COMMON_CFLAGS) 
App_C_Flags += -fPIC 
App_C_Flags += -Wno-attributes 
App_C_Flags += $(App_Include_Paths) 
App_C_Flags += -DPELZ_SGX_UNTRUSTED
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
App_Cpp_Flags += -DPELZ_SGX_UNTRUSTED

App_Link_Flags := -L$(SGX_SSL_UNTRUSTED_LIB_PATH) 
App_Link_Flags += -L$(SGX_LIBRARY_PATH) 
App_Link_Flags += -l$(Urts_Library_Name) 
App_Link_Flags += -lsgx_usgxssl 
App_Link_Flags += -lkmyth-logger 
App_Link_Flags += -lkmyth-utils 
App_Link_Flags += -lkmyth-tpm 
App_Link_Flags += -lpthread 
App_Link_Flags += -luriparser

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Name_Test    := pelz-test

App_Name_Service := pelz-service

App_Name_Pipe    := pelz

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Include_Paths := -Iinclude
Enclave_Include_Paths += -Isgx 
Enclave_Include_Paths += -I$(SGX_SDK)/include 
Enclave_Include_Paths += -I$(SGX_SDK)/include/tlibc 
Enclave_Include_Paths += -I$(SGX_SSL_INCLUDE_PATH) 
Enclave_Include_Paths += -I/usr/local/include
Enclave_Include_Paths += -Ikmyth/sgx/trusted/include
Enclave_Include_Paths += -Ikmyth/sgx/trusted/include/wrapper
Enclave_Include_Paths += -Ikmyth/sgx/trusted/include/util
Enclave_Include_Paths += -Ikmyth/sgx/common/include
Enclave_Include_Paths += -Ikmyth/include
Enclave_Include_Paths += -Ikmyth/include/protocol
Enclave_Include_Paths += -Ikmyth/include/cipher
Enclave_Include_Paths += -Ikmyth/utils/include/kmyth
Enclave_Include_Paths += -Itest/include

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) 
Enclave_C_Flags += -fPIC
Enclave_C_Flags += -Wno-attributes
Enclave_C_Flags += -nostdinc 
Enclave_C_Flags += -fvisibility=hidden 
Enclave_C_Flags += -fpie 
Enclave_C_Flags += -fstack-protector 
Enclave_C_Flags += $(Enclave_Include_Paths) 
Enclave_C_Flags += -DPELZ_SGX_TRUSTED
Enclave_C_Flags += -Wall 
Enclave_C_Flags += -DKMYTH_SGX

Enclave_Cpp_Flags := $(SGX_COMMON_CXXFLAGS)
Enclave_Cpp_Flags += -fpie
Enclave_Cpp_Flags += -std=c++03 
Enclave_Cpp_Flags += -std=c++11
Enclave_Cpp_Flags += -nostdinc++ 
Enclave_Cpp_Flags += --include "tsgxsslio.h" 
Enclave_Cpp_Flags += $(Enclave_Include_Paths)
Enclave_Cpp_Flags += -DPELZ_SGX_TRUSTED
Enclave_Cpp_Flags += -DKMYTH_SGX

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

Enclave_Name := pelz_enclave.so
Test_Enclave_Name := pelz_test_enclave.so
Enclave_Signing_Key := pelz_enclave_private.pem
Signed_Enclave_Name := pelz_enclave.signed.so
Signed_Test_Enclave_Name := pelz_test_enclave.signed.so
Enclave_Config_File := sgx/pelz_enclave.config.xml

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
Generate or install sgx/$(Enclave_Signing_Key)
e.g., run 'openssl genrsa -out sgx/$(Enclave_Signing_Key) -3 3072'
endef


.PHONY: all run test-run test-all

ifeq ($(Build_Mode), HW_RELEASE)
all: override ENCLAVE_HEADERS = -DENCLAVE_HEADER_TRUSTED=$(ENCLAVE_HEADER_TRUSTED) -DENCLAVE_HEADER_UNTRUSTED=$(ENCLAVE_HEADER_UNTRUSTED)
all: pre bin/$(App_Name_Service) bin/$(App_Name_Pipe) sgx/$(Signed_Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else			
all: override ENCLAVE_HEADERS = -DENCLAVE_HEADER_TRUSTED=$(ENCLAVE_HEADER_TRUSTED) -DENCLAVE_HEADER_UNTRUSTED=$(ENCLAVE_HEADER_UNTRUSTED)	
all: pre bin/$(App_Name_Service) bin/$(App_Name_Pipe) sgx/$(Signed_Enclave_Name)
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name_Service)
	@echo "RUN  =>  $(App_Name_Service) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

ifeq ($(Build_Mode), HW_RELEASE)
test-all: override ENCLAVE_HEADERS = -DENCLAVE_HEADER_TRUSTED=$(TEST_ENCLAVE_HEADER_TRUSTED) -DENCLAVE_HEADER_UNTRUSTED=$(TEST_ENCLAVE_HEADER_UNTRUSTED)
test-all: pre test/bin/$(App_Name_Test) sgx/$(Signed_Test_Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Test_Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Test_Enclave_Name) -out <$(Signed_Test_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
test-all: override ENCLAVE_HEADERS = -DENCLAVE_HEADER_TRUSTED=$(TEST_ENCLAVE_HEADER_TRUSTED) -DENCLAVE_HEADER_UNTRUSTED=$(TEST_ENCLAVE_HEADER_UNTRUSTED)
test-all: pre test/bin/$(App_Name_Test) sgx/$(Signed_Test_Enclave_Name)
endif

test-run: test-all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name_Test)
	@echo "RUN  =>  $(App_Name_Test) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## Common Objects ########

sgx/ec_key_cert_marshal.o: kmyth/sgx/common/src/ec_key_cert_marshal.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/ec_key_cert_unmarshal.o: kmyth/sgx/common/src/ec_key_cert_unmarshal.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/ecdh_util.o: kmyth/sgx/common/src/ecdh_util.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

######## App Objects ########

sgx/log_ocall.o: kmyth/sgx/untrusted/src/ocall/log_ocall.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/memory_ocall.o: kmyth/sgx/untrusted/src/ocall/memory_ocall.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/ecdh_ocall.o: kmyth/sgx/untrusted/src/ocall/ecdh_ocall.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/pelz_enclave_u.c: $(SGX_EDGER8R) sgx/pelz_enclave.edl
	@cd sgx && $(SGX_EDGER8R) --untrusted pelz_enclave.edl \
				  --search-path . \
				  --search-path $(SGX_SDK)/include \
				  --search-path $(SGX_SSL_INCLUDE_PATH) \
				  --search-path ../include \
				  --search-path ../kmyth/sgx/trusted
	@echo "GEN  =>  $@"


sgx/pelz_enclave_u.o: sgx/pelz_enclave_u.c
	@$(CC) $(App_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

test/include/test_enclave_u.c: $(SGX_EDGER8R) test/include/test_enclave.edl
	@cd test/include && $(SGX_EDGER8R) --untrusted test_enclave.edl \
                                           --search-path . \
                                           --search-path $(SGX_SDK)/include \
                                           --search-path $(SGX_SSL_INCLUDE_PATH) \
                                           --search-path ../../include \
                                           --search-path ../../kmyth/sgx/trusted \
                                           --search-path ../../sgx
	@echo "GEN  =>  $@"

sgx/test_enclave_u.o: test/include/test_enclave_u.c
	@$(CC) $(App_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"


test/bin/$(App_Name_Test): $(App_C_Test_Files) \
			   $(App_C_Files) \
				 src/util/cmd_interface.c \
				 src/util/seal.c \
			   $(App_C_Kmyth_Files) \
				 sgx/test_enclave_u.o \
				 sgx/ec_key_cert_marshal.o \
				 sgx/ec_key_cert_unmarshal.o \
				 sgx/log_ocall.o \
				 sgx/ecdh_ocall.o \
				 sgx/ecdh_util.o \
				 sgx/memory_ocall.o
	@$(CC) $^ -o $@ $(App_C_Flags) \
			 $(App_Include_Paths) \
			 -Isgx \
			 -Itest/include \
			 $(App_C_Flags) \
			 -g \
			 $(ENCLAVE_HEADERS) \
			 $(App_Link_Flags) \
			 -lcrypto \
			 -lcjson \
			 -lpthread \
			 -lcunit
	@echo "LINK =>  $(App_Name_Test)"

bin/$(App_Name_Service): $(App_Service_File) \
			 $(App_C_Files) \
			 $(App_C_Kmyth_Files) \
			 sgx/pelz_enclave_u.o \
			 sgx/ec_key_cert_unmarshal.o \
			 sgx/log_ocall.o \
			 sgx/ecdh_ocall.o \
			 sgx/ecdh_util.o \
			 sgx/memory_ocall.o 
	@$(CC) $^ -o $@ $(App_C_Flags) \
			 $(App_Include_Paths) \
			 -Isgx \
			 $(App_C_Flags) \
			 $(ENCLAVE_HEADERS) \
			 $(App_Link_Flags) \
			 -Lsgx \
			 -lcrypto \
			 -lcjson \
			 -lpthread
	@echo "LINK =>  $(App_Name_Service)"

bin/$(App_Name_Pipe): $(App_Pipe_File) \
		      $(App_C_Files) \
		      src/util/cmd_interface.c \
		      src/util/seal.c \
		      $(App_C_Kmyth_Files) \
		      sgx/pelz_enclave_u.o \
		      sgx/ec_key_cert_unmarshal.o \
		      sgx/log_ocall.o \
		      sgx/ecdh_ocall.o \
		      sgx/ecdh_util.o \
		      sgx/memory_ocall.o 
	@$(CC) $^ -o $@ $(App_C_Flags) \
			 $(App_Include_Paths) \
			 -Isgx \
			 $(App_C_Flags) \
			 $(ENCLAVE_HEADERS) \
			 $(App_Link_Flags) \
			 -Lsgx \
			 -lcrypto \
			 -lcjson \
			 -lpthread
	@echo "LINK =>  $(App_Name_Pipe)"

######## Enclave Objects ########

sgx/pelz_enclave_t.c: $(SGX_EDGER8R) sgx/pelz_enclave.edl
	@cd sgx && $(SGX_EDGER8R) --trusted pelz_enclave.edl \
				  --search-path . \
				  --search-path $(SGX_SDK)/include \
				  --search-path $(SGX_SSL_INCLUDE_PATH) \
				  --search-path ../include \
				  --search-path ../kmyth/sgx/trusted 
	@echo "GEN => $@"

sgx/pelz_enclave_t.o: sgx/pelz_enclave_t.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

test/include/test_enclave_t.c: $(SGX_EDGER8R) test/include/test_enclave.edl
	@cd test/include && $(SGX_EDGER8R) --trusted test_enclave.edl \
                                           --search-path . \
                                           --search-path $(SGX_SDK)/include \
                                           --search-path $(SGX_SSL_INCLUDE_PATH) \
                                           --search-path ../../include \
                                           --search-path ../../kmyth/sgx/trusted \
                                           --search-path ../../sgx 
	@echo "GEN => $@"

sgx/test_enclave_t.o: test/include/test_enclave_t.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

sgx/kmyth_enclave_seal.o: kmyth/sgx/trusted/src/ecall/kmyth_enclave_seal.cpp
	@$(CXX) $(Enclave_Cpp_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CXX   <=  $<"

sgx/kmyth_enclave_unseal.o: kmyth/sgx/trusted/src/ecall/kmyth_enclave_unseal.cpp
	@$(CXX) $(Enclave_Cpp_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CXX   <=  $<"

sgx/kmyth_enclave_memory_util.o: kmyth/sgx/trusted/src/util/kmyth_enclave_memory_util.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

sgx/kmyth_enclave_retrieve_key.o: kmyth/sgx/trusted/src/ecall/kmyth_enclave_retrieve_key.cpp
	@$(CXX) $(Enclave_Cpp_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CXX   <=  $<"

sgx/sgx_retrieve_key_impl.o: kmyth/sgx/trusted/src/wrapper/sgx_retrieve_key_impl.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

sgx/pelz_aes_gcm.o: src/cipher/pelz_aes_gcm.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

sgx/aes_gcm.o: kmyth/src/cipher/aes_gcm.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

sgx/memory_util.o: kmyth/utils/src/memory_util.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

sgx/kmip_util.o: kmyth/src/protocol/kmip_util.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC   <=  $<"

sgx/common_table.o: src/util/common_table.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

sgx/key_table.o: src/util/key_table.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

sgx/server_table.o: src/util/server_table.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

sgx/ca_table.o: src/util/ca_table.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

sgx/channel_table.o: src/util/channel_table.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

sgx/pelz_aes_keywrap_3394nopad.o: src/cipher/pelz_aes_keywrap_3394nopad.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

sgx/pelz_request_handler.o: src/util/pelz_request_handler.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

sgx/charbuf.o: src/util/charbuf.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

sgx/pelz_cipher.o: src/cipher/pelz_cipher.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

sgx/enclave_request_signing.o: src/util/enclave_request_signing.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"

sgx/secure_socket_enclave.o: src/util/secure_socket_enclave.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <=  $<"


sgx/$(Enclave_Name): sgx/pelz_enclave_t.o \
		     sgx/common_table.o \
		     sgx/key_table.o \
		     sgx/server_table.o \
	 	     sgx/channel_table.o \
		     sgx/pelz_aes_keywrap_3394nopad.o \
		     sgx/ca_table.o \
		     sgx/secure_socket_enclave.o \
		     sgx/pelz_request_handler.o \
		     sgx/charbuf.o \
		     sgx/kmyth_enclave_seal.o \
		     sgx/kmyth_enclave_unseal.o \
		     sgx/kmyth_enclave_memory_util.o \
		     sgx/kmyth_enclave_retrieve_key.o \
		     sgx/ec_key_cert_unmarshal.o \
		     sgx/ecdh_util.o \
		     sgx/sgx_retrieve_key_impl.o \
		     sgx/pelz_aes_gcm.o \
		     sgx/aes_gcm.o \
		     sgx/memory_util.o \
		     sgx/kmip_util.o \
		     sgx/pelz_cipher.o \
		     sgx/enclave_request_signing.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags) $(ENCLAVE_HEADERS)
	@echo "LINK =>  $@"

sgx/$(Enclave_Signing_Key):
	$(error $(err_no_enclave_signing_key))

sgx/$(Signed_Enclave_Name): sgx/$(Enclave_Name) sgx/$(Enclave_Signing_Key)
	@$(SGX_ENCLAVE_SIGNER) sign -key sgx/$(Enclave_Signing_Key) \
				    -enclave sgx/$(Enclave_Name) \
				    -out $@ \
				    -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

sgx/enclave_helper_functions.o: test/src/util/enclave_helper_functions.c
	@$(CC) $(Enclave_C_Flags) $(ENCLAVE_HEADERS) -c $< -o $@
	@echo "CC  <= $<"

sgx/$(Test_Enclave_Name): sgx/test_enclave_t.o \
			  sgx/common_table.o \
			  sgx/key_table.o \
			  sgx/server_table.o \
			  sgx/channel_table.o \
			  sgx/pelz_aes_keywrap_3394nopad.o \
			  sgx/pelz_request_handler.o \
			  sgx/charbuf.o \
			  sgx/kmyth_enclave_seal.o \
			  sgx/kmyth_enclave_unseal.o \
			  sgx/kmyth_enclave_memory_util.o \
			  sgx/kmyth_enclave_retrieve_key.o \
			  sgx/ec_key_cert_unmarshal.o \
			  sgx/ecdh_util.o \
			  sgx/sgx_retrieve_key_impl.o \
			  sgx/aes_gcm.o \
			  sgx/pelz_aes_gcm.o \
			  sgx/memory_util.o \
			  sgx/kmip_util.o \
			  sgx/enclave_helper_functions.o \
			  sgx/pelz_cipher.o \
			  sgx/ca_table.o \
			  sgx/secure_socket_enclave.o \
			  sgx/enclave_request_signing.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags) $(ENCLAVE_HEADERS)
	@echo "LINK =>	$@"

sgx/$(Signed_Test_Enclave_Name): sgx/$(Test_Enclave_Name) sgx/$(Enclave_Signing_Key)
	@$(SGX_ENCLAVE_SIGNER) sign -key sgx/$(Enclave_Signing_Key) \
                                    -enclave sgx/$(Test_Enclave_Name) \
                                    -out $@ \
                                    -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: pre

pre:
	@rm -f src/*/*.c~
	@rm -f include/*.h~
	@rm -f test/src/*.c~
	@rm -f test/src/*/*.c~
	@rm -f test/include/*.h~
	@mkdir -p bin
	@mkdir -p test/bin
	@mkdir -p test/log
	@mkdir -p test/data

.PHONY: test

test: all test-all
	@cd test/data && ./gen_test_keys_certs.bash
	@openssl x509 -in test/data/node_pub.pem -inform pem -out test/data/node_pub.der -outform der
	@openssl x509 -in test/data/proxy_pub.pem -inform pem -out test/data/proxy_pub.der -outform der
	@openssl pkey -in test/data/node_priv.pem -inform pem -out test/data/node_priv.der -outform der
	@openssl x509 -in test/data/ca_pub.pem -inform pem -out test/data/ca_pub.der -outform der
	@echo "GEN => Test Key/Cert Files"
	@cd kmyth/sgx && make demo-pre demo/bin/ecdh-server --eval="Demo_App_C_Flags += -DDEMO_LOG_LEVEL=LOG_WARNING"
	@./kmyth/sgx/demo/bin/ecdh-server -r test/data/proxy_priv.pem -u test/data/node_pub.pem -p 7000 -m 1 2> /dev/null &
	@sleep 1
	@./test/bin/pelz-test 2> /dev/null
	@rm -f test/data/*.pem
	@rm -f test/data/*.der
	@rm -f test/data/*.nkl
	@rm -f test/data/*.csr
	@rm -f test/data/*.srl

.PHONY: install-test-vectors

install-test-vectors: uninstall-test-vectors
	mkdir -p test/data/kwtestvectors
	wget https://csrc.nist.gov/groups/STM/cavp/documents/mac/kwtestvectors.zip
	unzip kwtestvectors.zip -d test/data
	rm kwtestvectors.zip

.PHONY: uninstall-test-vectors

uninstall-test-vectors:
	rm -rf test/data/kwtestvectors

.PHONY: clean

clean:
	@rm -f bin/pelz
	@rm -f bin/pelz-service
	@rm -f test/bin/pelz-test
	@rm -f sgx/*.so
	@rm -f sgx/*_u.*
	@rm -f sgx/*_t.*
	@rm -f sgx/*.o
	@rm -f test/include/*_u.*
	@rm -f test/include/*_t.*
	@rm -f test/log/*
	@rm -f test/data/*.pem
	@rm -f test/data/*.der
	@rm -f test/data/*.nkl
	@rm -f test/data/*.txt
	@rm -f test/data/*.csr
	@rm -f test/data/*.srl
	@cd kmyth/sgx && make clean
	@cd attestation_demo && make clean
