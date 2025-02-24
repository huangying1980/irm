#huangying
CC := gcc
VPATH := ./:./runtime
AR := ar
TARGET ?= release
RELEASE := -mtune=native -march=native -O3 -fomit-frame-pointer -fforce-addr -fivopts -ftree-vectorize -fweb -frename-registers -ftree-loop-linear -fno-bounds-check
CFLAGS := -Wall -Werror -pthread -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
INC := -I../ -I./ -I../include -Ideps
LIB := -pthread -Ldeps -lciul1
MAJOR := 1
MINOR := 0
SMALL := 0
VERSION := -DIRM_MAJOR=$(MAJOR) -DIRM_MINOR=$(MINOR) -DIRM_SMALL=$(SMALL)
LDFLAGS := -Wl,--version-script=./irm.ld
DEBUG :=
ifeq ($(TARGET),debug)
    DEBUG := -DIRM_ERROR_VERBOSE -DIRM_DEBUG_VERBOSE
    AR_TARGET := libirm.a.dbg.$(MAJOR).$(MINOR).$(SMALL)
    SO_TARGET := libirm.so.dbg.$(MAJOR).$(MINOR).$(SMALL)
else
    AR_TARGET := libirm.a.$(MAJOR).$(MINOR).$(SMALL)
    SO_TARGET := libirm.so.$(MAJOR).$(MINOR).$(SMALL)
endif
SRC := $(wildcard *.c)
AR_OBJ := $(SRC:%.c=%.a.o)
SO_OBJ := $(SRC:%.c=%.so.o)

.PHONY: all clean install debug


all: $(AR_TARGET) $(SO_TARGET) install

	
$(SO_OBJ): %.so.o:%.c
	$(CC) -c $< -o $@ $(INC) $(CFLAGS) -fPIC $(VERSION) $(DEBUG) $(RELEASE)

$(SO_TARGET): $(SO_OBJ)
	$(CC) $^ -o $@ $(LIB) $(LDFLAGS) -shared $(DEBUG) $(RELEASE)

$(AR_OBJ): %.a.o:%.c
	$(CC) -c $< -o $@ $(INC) $(CFLAGS) $(VERSION) $(DEBUG) $(RELEASE)

$(AR_TARGET):$(AR_OBJ)
	$(AR) rcs $@ $^

install:
	cp $(AR_TARGET) ../libs
	cp $(SO_TARGET) ../libs

clean:
	rm -rf *.o $(SO_TARGET)
	rm -rf libirm.a.* libirm.so.*
