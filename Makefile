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

ENCLAVE_HEADER_TRUSTED ?= '"pelz_enclave_t.h"'
ENCLAVE_HEADER_UNTRUSTED ?= '"pelz_enclave_u.h"'

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
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
		SGX_COMMON_CFLAGS += -O0 -g
else
		SGX_COMMON_CFLAGS += -O2
endif

# Specify indentation options
INDENT_OPTS = -bli0#                     indent braces zero spaces
INDENT_OPTS += -bap#                     blank lines after procedure bodies
INDENT_OPTS += -bad#                     blank lines after declarations
INDENT_OPTS += -sob#                     swallow optional blank lines
INDENT_OPTS += -cli0#                    case label indent of zero spaces
INDENT_OPTS += -npcs#                    no space after function in calls
INDENT_OPTS += -nbc#                     don't force newlines after commas
INDENT_OPTS += -bls#                     put braces on line after struct decl
INDENT_OPTS += -blf#                     put braces on line after func def
INDENT_OPTS += -nlp#                     align continued lines at parentheses
INDENT_OPTS += -ip0#                     indent parameter types zero spaces
INDENT_OPTS += -ts2#                     set tab size to two spaces
INDENT_OPTS += -nut#                     use spaces instead of tabs
INDENT_OPTS += -npsl#                    type of proc on same line as name
INDENT_OPTS += -bbo#                     prefer break before boolean operator
INDENT_OPTS += -l128#                    max non-comment line length is 128

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Service_File := src/pelz-service/main.c

App_Pipe_File := src/pelz/main.c

App_Cpp_Files := src/util/charbuf.c \
		 src/util/pelz_json_parser.c \
		 src/util/pelz_service.c \
		 src/util/pelz_socket.c \
		 src/util/pelz_thread.c \
		 src/util/util.c \
		 src/util/pelz_io.c \
		 src/util/pelz_uri_helpers.c \
		 src/util/pelz_key_loaders.c

App_Cpp_Test_Files := test/src/pelz_test.c \
		 test/src/util/enclave_test_suite.c \
		 test/src/util/pelz_json_parser_test_suite.c \
	 	 test/src/util/util_test_suite.c \
		 test/src/util/test_helper_functions.c \
		 test/src/util/test_pelz_uri_helpers.c

App_Cpp_Kmyth_Files := kmyth/sgx/untrusted/src/wrapper/sgx_seal_unseal_impl.c

App_Include_Paths := -Iinclude 
App_Include_Paths += -Isgx 
App_Include_Paths += -I$(SGX_SDK)/include 
App_Include_Paths += -Ikmyth/sgx/untrusted/include/wrapper
App_Include_Paths += -Ikmyth/sgx/untrusted/include/ocall
App_Include_Paths += -Ikmyth/sgx/common/include

App_C_Flags := $(SGX_COMMON_CFLAGS) 
App_C_Flags += -fPIC 
App_C_Flags += -Wno-attributes 
App_C_Flags += $(App_Include_Paths) 
App_C_Flags += -DPELZ_SGX_UNTRUSTED
App_C_Flags += -Wall
App_C_Flags += -DENCLAVE_HEADER_UNTRUSTED=$(ENCLAVE_HEADER_UNTRUSTED)

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

App_Cpp_Flags := $(App_C_Flags) -std=c++11 -DPELZ_SGX_UNTRUSTED

App_Link_Flags := $(SGX_COMMON_CFLAGS) 
App_Link_Flags += -L$(SGX_SSL_UNTRUSTED_LIB_PATH) 
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
Enclave_Include_Paths += -Isgx/include 
Enclave_Include_Paths += -I$(SGX_SDK)/include 
Enclave_Include_Paths += -I$(SGX_SDK)/include/tlibc 
Enclave_Include_Paths += -I$(SGX_SDK)/include/stlport 
Enclave_Include_Paths += -I$(SGX_SSL_INCLUDE_PATH) 
Enclave_Include_Paths += -Isgx 
Enclave_Include_Paths += -Ikmyth/sgx/trusted/include
Enclave_Include_Paths += -Ikmyth/sgx/trusted/include/util
Enclave_Include_Paths += -Ikmyth/sgx/common/include

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) 
Enclave_C_Flags += -nostdinc 
Enclave_C_Flags += -fvisibility=hidden 
Enclave_C_Flags += -fpie 
Enclave_C_Flags += -fstack-protector 
Enclave_C_Flags += $(Enclave_Include_Paths) 
Enclave_C_Flags += -DPELZ_SGX_TRUSTED
Enclave_C_Flags += -Wall 
Enclave_C_Flags += -DENCLAVE_HEADER_TRUSTED=$(ENCLAVE_HEADER_TRUSTED)

Enclave_Cpp_Flags := $(Enclave_C_Flags) 
Enclave_Cpp_Flags += -std=c++03 
Enclave_Cpp_Flags += -nostdinc++ 
Enclave_Cpp_Flags += --include "tsgxsslio.h" 
Enclave_Cpp_Flags += -Wall

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) 
Enclave_Link_Flags += -Wl,--no-undefined 
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

Enclave_Name := pelz_enclave.so
Enclave_Signing_Key := pelz_enclave_private.pem
Signed_Enclave_Name := pelz_enclave.signed.so
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


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: pre bin/$(App_Name_Service) bin/$(App_Name_Pipe) test/bin/$(App_Name_Test) sgx/$(Signed_Enclave_Name)
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name_Service)
	@echo "RUN  =>  $(App_Name_Service) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## Common Objects ########

sgx/ec_key_cert_unmarshal.o: kmyth/sgx/common/src/ec_key_cert_unmarshal.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

######## App Objects ########

sgx/log_ocall.o: kmyth/sgx/untrusted/src/ocall/log_ocall.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/pelz_enclave_u.c: $(SGX_EDGER8R) sgx/pelz_enclave.edl
	@cd sgx && $(SGX_EDGER8R) --untrusted pelz_enclave.edl \
				  --search-path . \
				  --search-path include \
				  --search-path $(SGX_SDK)/include \
				  --search-path $(SGX_SSL_INCLUDE_PATH) \
				  --search-path ../include \
				  --search-path ../kmyth/sgx/trusted
	@echo "GEN  =>  $@"

sgx/pelz_enclave_u.o: sgx/pelz_enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

test/bin/$(App_Name_Test): $(App_Cpp_Test_Files) \
			   $(App_Cpp_Files) \
			   $(App_Cpp_Kmyth_Files) \
			   sgx/pelz_enclave_u.o \
			   sgx/ec_key_cert_unmarshal.o \
			   sgx/log_ocall.o
	@$(CXX) $^ -o $@ $(App_Cpp_Flags) \
			 $(App_Include_Paths) \
			 -Itest/include \
			 -Isgx \
			 $(App_C_Flags) \
			 $(App_Link_Flags) \
			 -Lsgx \
			 -lcrypto \
			 -lcjson \
			 -lpthread \
			 -lcunit
	@echo "LINK =>  $@"

bin/$(App_Name_Service): $(App_Service_File) \
			 $(App_Cpp_Files) \
			 $(App_Cpp_Kmyth_Files) \
			 sgx/pelz_enclave_u.o \
			 sgx/ec_key_cert_unmarshal.o \
			 sgx/log_ocall.o
	@$(CXX) $^ -o $@ $(App_Cpp_Flags) \
			 $(App_Include_Paths) \
			 -Isgx \
			 $(App_C_Flags) \
			 $(App_Link_Flags) \
			 -Lsgx \
			 -lcrypto \
			 -lcjson \
			 -lpthread
	@echo "LINK =>  $@"

bin/$(App_Name_Pipe): $(App_Pipe_File) \
		      $(App_Cpp_Files) \
		      $(App_Cpp_Kmyth_Files) \
		      sgx/pelz_enclave_u.o \
		      sgx/ec_key_cert_unmarshal.o \
		      sgx/log_ocall.o
	@$(CXX) $^ -o $@ $(App_Cpp_Flags) \
			 $(App_Include_Paths) \
			 -Isgx \
			 $(App_C_Flags) \
			 $(App_Link_Flags) \
			 -Lsgx \
			 -lcrypto \
			 -lcjson \
			 -lpthread
	@echo "LINK =>  $@"

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
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/kmyth_enclave_seal.o: kmyth/sgx/trusted/src/ecall/kmyth_enclave_seal.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
sgx/kmyth_enclave_unseal.o: kmyth/sgx/trusted/src/ecall/kmyth_enclave_unseal.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/kmyth_enclave_memory_util.o: kmyth/sgx/trusted/src/util/kmyth_enclave_memory_util.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/kmyth_enclave_retrieve_key.o: kmyth/sgx/trusted/src/ecall/kmyth_enclave_retrieve_key.cpp
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx/key_table.o: src/util/key_table.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

sgx/server_table.o: src/util/server_table.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

sgx/aes_keywrap_3394nopad.o: src/util/aes_keywrap_3394nopad.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

sgx/pelz_request_handler.o: src/util/pelz_request_handler.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

sgx/charbuf.o: src/util/charbuf.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

sgx/util.o: src/util/util.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <= $<"

sgx/$(Enclave_Name): sgx/pelz_enclave_t.o \
		     sgx/key_table.o \
		     sgx/aes_keywrap_3394nopad.o \
		     sgx/pelz_request_handler.o \
		     sgx/charbuf.o \
		     sgx/util.o \
		     sgx/server_table.o \
		     sgx/kmyth_enclave_seal.o \
	     	     sgx/kmyth_enclave_unseal.o \
		     sgx/kmyth_enclave_memory_util.o \
		     sgx/kmyth_enclave_retrieve_key.o \
		     sgx/ec_key_cert_unmarshal.o
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

sgx/$(Enclave_Signing_Key):
	$(error $(err_no_enclave_signing_key))

sgx/$(Signed_Enclave_Name): sgx/$(Enclave_Name) sgx/$(Enclave_Signing_Key)
	@$(SGX_ENCLAVE_SIGNER) sign -key sgx/$(Enclave_Signing_Key) \
				    -enclave sgx/$(Enclave_Name) \
				    -out $@ \
				    -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: pre

pre:
	@indent $(INDENT_OPTS) src/*/*.c
	@indent $(INDENT_OPTS) include/*.h
	@indent $(INDENT_OPTS) test/src/*.c
	@indent $(INDENT_OPTS) test/src/*/*.c
	@indent $(INDENT_OPTS) test/include/*.h
	@rm -f src/*/*.c~
	@rm -f include/*.h~
	@rm -f test/src/*.c~
	@rm -f test/src/*/*.c~
	@rm -f test/include/*.h~
	@mkdir -p bin
	@mkdir -p test/bin
	@mkdir -p test/log


.PHONY: test

test: all
	@./test/bin/pelz-test 2> /dev/null

.PHONY: clean

clean:
	@rm -f bin/pelz
	@rm -f bin/pelz-service
	@rm -f test/bin/pelz-test
	@rm -f sgx/pelz_enclave.signed.so
	@rm -f sgx/pelz_enclave.so
	@rm -f sgx/*_u.*
	@rm -f sgx/*_t.*
	@rm -f sgx/*.o
	@rm -f test/log/*

