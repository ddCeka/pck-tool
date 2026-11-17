CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2 -I.

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl@3)
    CFLAGS += -I$(OPENSSL_PREFIX)/include
    LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lcrypto
else ifeq ($(UNAME_S), Linux)
    LDFLAGS = -lcrypto
else
    $(error Unsupported OS: $(UNAME_S). Only Linux and macOS are supported.)
endif

TARGET = pckt
SOURCES = main.c files.c common.c pckProcess.c
OBJECTS = $(SOURCES:.c=.o)
LIB_OBJECTS = files.o common.o pckProcess.o
HEADERS = files.h common.h pckProcess.h

TEST_DIR = test
TEST_SOURCE = $(TEST_DIR)/test_pckt.c
TEST_TARGET = $(TEST_DIR)/test_pckt

.PHONY: all strip test clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $(TARGET)

strip: $(TARGET)
	strip $(TARGET)

$(TEST_TARGET): $(TEST_SOURCE) $(LIB_OBJECTS) $(HEADERS)
	$(CC) $(CFLAGS) $(TEST_SOURCE) $(LIB_OBJECTS) $(LDFLAGS) -o $(TEST_TARGET)

test: $(TARGET) $(TEST_TARGET)
	./$(TEST_TARGET)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) $(TEST_TARGET)
