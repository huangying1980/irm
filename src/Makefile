#huangying
CC := gcc
VPATH := ./:./runtime
AR := ar
TARGET ?= release

IRM_EFVI ?= off
IRM_DPDK ?= off
IRM_XDP ?= off


ifeq ($(IRM_DPDK), on)
$(error ERROR: Support for DPDK under development)
DPDK_LIB :=
DPDK_INC :=
DPDK_SRC :=
DPDK_CFLAGS := -DIRM_ENABLE_DPDK
endif

ifeq ($(IRM_XDP), on)
$(error ERROR: Support for XDP is on the roadmap)
XDP_LIB :=
XDP_INC :=
XDP_SRC :=
XDP_CFLAGS := -DIRM_ENABLE_XDP
endif

ifeq ($(IRM_EFVI), on)
EFVI_LIB := -L../deps/efvi -lciul1
EFVI_INC := -I../deps/efvi
EFVI_SRC := irm_efvi_netio.c
EFVI_CFLAGS := -DIRM_ENABLE_EFVI
endif

#MPOOL_LIB := -L../deps/mpool -Wl,-Bstatic -lmpool -Wl,-Bdynamic
MPOOL_LIB := ../deps/mpool/libmpool.a
MPOOL_INC := -I../deps/mpool

RELEASE := -mtune=native -march=native -O3 -fomit-frame-pointer -fforce-addr -fivopts -ftree-vectorize -fweb -frename-registers -ftree-loop-linear -fno-bounds-check
CFLAGS := -Wall -Werror -pthread -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $(EFVI_CFLAGS) $(DPDK_CFLAGS) $(XDP_CFLAGS)
INC := -I../ -I./ -I../include $(MPOOL_INC) $(EFVI_INC) $(DPDK_INC) $(XDP_INC)
LIB := -pthread $(MPOOL_LIB) $(EFVI_LIB) $(DPDK_LIB) $(XDP_LIB)
MAJOR := 1
MINOR := 0
SMALL := 0
VERSION := -DIRM_MAJOR=$(MAJOR) -DIRM_MINOR=$(MINOR) -DIRM_SMALL=$(SMALL)
LDFLAGS := -Wl,--version-script=./irm.ver
DEBUG :=
ifeq ($(TARGET),debug)
    DEBUG := -DIRM_ERROR_VERBOSE -DIRM_DEBUG_VERBOSE
    AR_TARGET := libirm.a.dbg.$(MAJOR).$(MINOR).$(SMALL)
    SO_TARGET := libirm.so.dbg.$(MAJOR).$(MINOR).$(SMALL)
else
    AR_TARGET := libirm.a.$(MAJOR).$(MINOR).$(SMALL)
    SO_TARGET := libirm.so.$(MAJOR).$(MINOR).$(SMALL)
endif

ALL_SRC := $(wildcard *.c)
SRC := $(ALL_SRC)

ifneq ($(IRM_EFVI), on)
SRC := $(filter-out irm_efvi_netio.c, $(ALL_SRC))
endif

ifneq ($(IRM_DPDK), on)
endif

ifneq ($(IRM_XDP), on)
endif

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
	mkdir ../libs
	cp $(AR_TARGET) ../libs
	cp $(SO_TARGET) ../libs
	ln -s ../libs/$(SO_TARGET) ../libs/libirm.so

clean:
	rm -rf *.o $(SO_TARGET)
	rm -rf libirm.a.* libirm.so.*
	rm -rf ../libs

debug:
	echo $(ALL_SRC)
	echo $(CFLAGS)
	echo $(INC)	
	echo $(LIB)
	echo $(SRC)
