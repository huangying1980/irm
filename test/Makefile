#huangying
CC := gcc
VPATH := ./:../
#TEST := -DIRM_TEST_LOST
RELEASE := -mtune=native -march=native -O3 -fomit-frame-pointer -fforce-addr -fivopts -ftree-vectorize -fweb -frename-registers -ftree-loop-linear -fno-bounds-check
#IRMFLAGS += -DIRM_NACK_TIMEOUT_STATIC
CFLAGS += -Wall -Werror -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -pthread $(IRMFLAGS) #-O3 #-O2 -O
#DEBUG := -DIRM_DEBUG_VERBOSE -DIRM_ERROR_VERBOSE -g -fsanitize=address -fno-omit-frame-pointer -static-libasan
#DEBUG := -DIRM_TRACE -DIRM_ERROR_VERBOSE -DIRM_DEBUG_VERBOSE #-g -fsanitize=address -fno-omit-frame-pointer -static-libasan
#LDFLAGS := -static-libasan
#LIB := -pthread -L../src/deps -lciul1
LIB := -pthread -L../deps/efvi -L../libs -lirm -lciul1
HEADER := -I../include -I../deps/efvi
TARGET := test
#SRC := $(wildcard test_*.cc ../src/*.cc)
SRC := $(wildcard test_*.c)
TEST_SRC := $(SRC:*_info.c=)
OBJ := $(TEST_SRC:%.c=%.o)

all: $(TARGET)

$(OBJ): %.o:%.c
	$(CC) -c $< -o $@ $(DEBUG) $(CFLAGS) $(HEADER) $(TEST) $(RELEASE)


$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LIB) $(DEBUG) $(RELEASE) $(LDFLAGS)
	ln -s $(TARGET) test_sub
	ln -s $(TARGET) test_pub
	ln -s $(TARGET) test_unremitting_pub
	ln -s $(TARGET) test_ping
	ln -s $(TARGET) test_pong

clean:
	rm -rf $(OBJ) $(TARGET)
	rm -rf test_sub test_pub test_unremitting_pub test_ping test_pong

.PHONY: all
