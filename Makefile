# Makefile for Pelz
PREFIX = /usr/local

CC = gcc -std=c11 #-DTIMEOUTSEC=1 -DTIMEOUTUSEC=0
DEBUG = -g

INCLUDES = 
LLIBS = 
CFLAGS = -Wall -c $(DEBUG) -D_GNU_SOURCE $(INCLUDES) 
LFLAGS = -Wall $(DEBUG) -lcrypto -lssl -pthread -lcjson -lkmyth-logger


OBJ_DIR = objs
SRC_DIR = src
TEST_DIR = test

INCLUDE_DIR = include

PELZ_SRC_DIR = $(SRC_DIR)/pelz
PELZ_OBJ_DIR = $(OBJ_DIR)/pelz

UTIL_SRC_DIR = $(SRC_DIR)/util
UTIL_OBJ_DIR = $(OBJ_DIR)/util

TEST_SRC_DIR = $(TEST_DIR)/src
TEST_OBJ_DIR = $(OBJ_DIR)

TEST_HEADER_FILES = $(wildcard $(TEST_DIR)/include/*h)

HEADER_FILES = $(wildcard $(INCLUDE_DIR)/*h)

PELZ_SOURCES = $(wildcard $(PELZ_SRC_DIR)/*c)
PELZ_OBJECTS = $(subst $(PELZ_SRC_DIR), $(PELZ_OBJ_DIR), $(PELZ_SOURCES:%.c=%.o))

UTIL_SOURCES = $(wildcard $(UTIL_SRC_DIR)/*c)
UTIL_OBJECTS = $(subst $(UTIL_SRC_DIR), $(UTIL_OBJ_DIR), $(UTIL_SOURCES:%.c=%.o))

TEST_SOURCES = $(wildcard $(TEST_SRC_DIR)/*.c $(TEST_SRC_DIR)/util/*.c)
TEST_OBJECTS = $(subst $(TEST_SRC_DIR), $(TEST_OBJ_DIR), $(TEST_SOURCES:%.c=%.o))

OBJECTS= $(PELZ_OBJECTS) $(UTIL_OBJECTS) $(TEST_UNIT_OBJECTS)

all: pre pelz

pelz: $(PELZ_OBJECTS) $(UTIL_OBJECTS)
	$(CC) $(PELZ_OBJECTS) $(UTIL_OBJECTS) -o bin/pelz $(LLIBS) $(LFLAGS)
	
test_unit: $(UTIL_OBJECTS) $(TEST_OBJECTS)
	$(CC) $(UTIL_OBJECTS) $(TEST_OBJECTS) -o test/bin/pelz-test $(LLIBS) -lcunit $(LFLAGS) -I$(INCLUDE_DIR)

pre:
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -nlp -ip0 -ts2 -nut -npsl -bbo -l128 src/*/*.c
	indent -bli0 -bap -bad -sob -cli0 -npcs -nbc -bls -blf -nlp -ip0 -ts2 -nut -npsl -bbo -l128 include/*.h
	rm -f src/*/*.c~
	rm -f include/*.h~
	mkdir -p bin
	mkdir -p test/bin
	mkdir -p test/log

test: test_unit
	./test/bin/pelz-test 2> /dev/null

docs: $(HEADER_FILES) $(CRYPRO_SOURCES) Doxyfile
	doxygen Doxyfile 

$(PELZ_OBJ_DIR)/%.o: $(PELZ_SRC_DIR)/%.c | $(PELZ_OBJ_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(UTIL_OBJ_DIR)/%.o: $(UTIL_SRC_DIR)/%.c | $(UTIL_OBJ_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(TEST_OBJ_DIR)/%.o: $(TEST_SRC_DIR)/%.c | $(TEST_OBJ_DIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -I$(TEST_DIR)/include -c $< -o $@

$(PELZ_OBJ_DIR):
	mkdir -p $(OBJ_DIR) $(PELZ_OBJ_DIR)
	
$(UTIL_OBJ_DIR):
	mkdir -p $(OBJ_DIR) $(UTIL_OBJ_DIR)

$(TEST_OBJ_DIR):
	mkdir -p $(OBJ_DIR) $(TEST_OBJ_DIR)

.PHONY: install
install:
	mkdir -p $(PREFIX)/bin
	cp bin/pelz $(PREFIX)/bin
	chmod 711 $(PREFIX)/bin/pelz
	mkdir -p /var/log

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/bin/pelz
	rm -f var/log/pelz.log

clean:
	-rm -fr $(OBJECTS) bin/pelz test/bin/pelz-test
	-rm -fr  test/log/pelz.log 
