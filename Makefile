CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
CPPFLAGS += -I.
LDFLAGS +=
LDLIBS += -lcrypto

PREFIX ?= /usr/local
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null)
    ifneq ($(OPENSSL_PREFIX),)
        CPPFLAGS += -I$(OPENSSL_PREFIX)/include
        LDFLAGS += -L$(OPENSSL_PREFIX)/lib
    endif
    STRIP_FLAGS = -x
else ifeq ($(UNAME_S), Linux)
    STRIP_FLAGS =
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

.PHONY: all debug strip test install uninstall clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $(TARGET)

debug: CFLAGS = -std=c11 -Wall -Wextra -g -O1 -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean $(TARGET) $(TEST_TARGET)
	./$(TEST_TARGET)

strip: $(TARGET)
	strip $(STRIP_FLAGS) $(TARGET)

$(TEST_TARGET): $(TEST_SOURCE) $(LIB_OBJECTS) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TEST_SOURCE) $(LIB_OBJECTS) $(LDFLAGS) $(LDLIBS) -o $(TEST_TARGET)

test: $(TARGET) $(TEST_TARGET)
	./$(TEST_TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)

%.o: %.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) $(TEST_TARGET)
