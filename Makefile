CC ?= gcc
AR ?= ar
RANLIB ?= ranlib
STRIP ?= strip
CFLAGS ?= -O2 -g
STATIC ?= 1
CROSS_COMPILE ?=
TARGET ?= native

ifneq ($(CROSS_COMPILE),)
TARGET := $(notdir $(patsubst %-,%,$(CROSS_COMPILE)))
CC := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar
RANLIB := $(CROSS_COMPILE)ranlib
STRIP := $(CROSS_COMPILE)strip
OPENSSL_TARGET ?= linux-generic32
CMAKE_CROSS_FLAGS := -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_C_COMPILER=$(CC) -DCMAKE_AR=$(AR) -DCMAKE_RANLIB=$(RANLIB)
else
OPENSSL_TARGET ?= linux-x86_64
endif

NGHTTP2_VERSION := 1.64.0
DEPS_PREFIX := $(CURDIR)/.deps/$(TARGET)
NGHTTP2_PREFIX := $(DEPS_PREFIX)/nghttp2
NGHTTP2_BUILD := $(CURDIR)/.deps/build/$(TARGET)/nghttp2
NGHTTP2_LIB := $(NGHTTP2_PREFIX)/lib/libnghttp2.a
OPENSSL_VERSION := 1.1.1w
OPENSSL_PREFIX := $(DEPS_PREFIX)/openssl
OPENSSL_LIBSSL := $(OPENSSL_PREFIX)/lib/libssl.a
OPENSSL_LIBCRYPTO := $(OPENSSL_PREFIX)/lib/libcrypto.a
OPENSSL_STAMP := $(OPENSSL_PREFIX)/.built

SRC := src/main.c src/util.c src/capnp_minimal.c src/control_stream.c src/edge_h2.c
BUILD_DIR := $(CURDIR)/.build/$(TARGET)
OBJ := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(SRC))
BIN := cloudflared-mini

CPPFLAGS += -D_POSIX_C_SOURCE=200112L -Iinclude -I$(NGHTTP2_PREFIX)/include
CFLAGS += -std=c11 -Wall -Wextra -Wno-unused-parameter
ifeq ($(STATIC),1)
CPPFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -static
LDLIBS := $(NGHTTP2_LIB) $(OPENSSL_LIBSSL) $(OPENSSL_LIBCRYPTO) -ldl -lpthread
DEPLIBS := $(NGHTTP2_LIB) $(OPENSSL_LIBSSL) $(OPENSSL_LIBCRYPTO)
else
LDLIBS := $(NGHTTP2_LIB) -lssl -lcrypto -lz -ldl -lpthread
DEPLIBS := $(NGHTTP2_LIB)
endif

.PHONY: all clean distclean deps

all: $(BIN)

deps: $(DEPLIBS)

$(NGHTTP2_LIB):
	mkdir -p .deps/src .deps/build
	test -f .deps/src/nghttp2-$(NGHTTP2_VERSION).tar.gz || \
	  curl -L -o .deps/src/nghttp2-$(NGHTTP2_VERSION).tar.gz \
	    https://github.com/nghttp2/nghttp2/releases/download/v$(NGHTTP2_VERSION)/nghttp2-$(NGHTTP2_VERSION).tar.gz
	rm -rf .deps/src/nghttp2-$(NGHTTP2_VERSION)
	tar -C .deps/src -xf .deps/src/nghttp2-$(NGHTTP2_VERSION).tar.gz
	cmake -S .deps/src/nghttp2-$(NGHTTP2_VERSION) -B $(NGHTTP2_BUILD) \
	  -DCMAKE_INSTALL_PREFIX=$(NGHTTP2_PREFIX) \
	  -DCMAKE_BUILD_TYPE=Release \
	  $(CMAKE_CROSS_FLAGS) \
	  -DBUILD_SHARED_LIBS=OFF \
	  -DBUILD_STATIC_LIBS=ON \
	  -DENABLE_LIB_ONLY=ON \
	  -DENABLE_APP=OFF \
	  -DENABLE_EXAMPLES=OFF \
	  -DENABLE_DOC=OFF \
	  -DENABLE_TESTS=OFF \
	  -DBUILD_TESTING=OFF
	cmake --build $(NGHTTP2_BUILD) --target install -j$$(nproc)

$(OPENSSL_LIBSSL) $(OPENSSL_LIBCRYPTO): $(OPENSSL_STAMP)

$(OPENSSL_STAMP):
	mkdir -p .deps/src
	test -f .deps/src/openssl-$(OPENSSL_VERSION).tar.gz || \
	  curl -L -o .deps/src/openssl-$(OPENSSL_VERSION).tar.gz \
	    https://www.openssl.org/source/openssl-$(OPENSSL_VERSION).tar.gz
	rm -rf .deps/src/openssl-$(OPENSSL_VERSION)
	tar -C .deps/src -xf .deps/src/openssl-$(OPENSSL_VERSION).tar.gz
	cd .deps/src/openssl-$(OPENSSL_VERSION) && \
	  ./Configure $(OPENSSL_TARGET) no-shared no-tests no-zlib no-async no-engine no-asm \
	    --cross-compile-prefix=$(CROSS_COMPILE) \
	    --prefix=$(OPENSSL_PREFIX) --openssldir=$(OPENSSL_PREFIX)/ssl && \
	  $(MAKE) -j$$(nproc) && \
	  $(MAKE) install_sw
	touch $(OPENSSL_STAMP)

$(BIN): $(DEPLIBS) $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

$(OBJ): $(DEPLIBS)

$(BUILD_DIR)/%.o: src/%.c
	mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(BIN)

distclean: clean
	rm -rf .deps .build
