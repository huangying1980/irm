#huangying
CC := gcc
VPATH := ./:../
RELEASE := -mtune=native -march=native -O3 -fomit-frame-pointer -fforce-addr -fivopts -ftree-vectorize -fweb -frename-registers -ftree-loop-linear -fno-bounds-check
CFLAGS += -Wall -Werror -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -pthread $(IRMFLAGS) #-O3 #-O2 -O
LIB := -pthread -L../src/deps -L../libs -lirm -lciul1
HEADER := -I../include -I../src/deps
TARGET := test
SRC := $(wildcard test_*.c)
OBJ := $(SRC:%.c=%.o)

all: $(TARGET)
	echo $(SRC) $(OBJ)
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




