APP = seal_data
APP_C_SRCS = seal_data.c

CC = riscv64-unknown-linux-gnu-gcc
CFLAGS = -Wall 
LINK = riscv64-unknown-linux-gnu-ld
AS = riscv64-unknown-linux-gnu-as

SDK_LIB_DIR = $(PENGLAI_SDK)/lib
MUSL_LIB_DIR = $(PENGLAI_SDK)/musl/lib
MUSL_LIBC = $(MUSL_LIB_DIR)/libc.a
GCC_LIB = $(SDK_LIB_DIR)/libgcc.a
SDK_EAPP_LIB = $(SDK_LIB_DIR)/libpenglai-enclave-eapp.a
SDK_EAPP_INCLUDE_DIR = $(SDK_LIB_DIR)/app/include
SDK_GM_LIB = $(SDK_LIB_DIR)/libpenglai-enclave-gm.a
SDK_GM_INCLUDE_DIR = $(SDK_LIB_DIR)/gm/include

LDFLAGS = -static -L$(SDK_LIB_DIR) -L$(MUSL_LIB_DIR) -lpenglai-enclave-gm -lpenglai-enclave-eapp -lc
CFLAGS += -I$(SDK_EAPP_INCLUDE_DIR) -I$(SDK_GM_INCLUDE_DIR) -I$(SDK_GM_INCLUDE_DIR)/miracl

APP_C_OBJS = $(patsubst %.c,%.o, $(APP_C_SRCS))
APP_LDS ?= $(PENGLAI_SDK)/app.lds

APP_BIN = $(patsubst %,%,$(APP))

all: $(APP_BIN)

$(APP_C_OBJS): %.o: %.c
	echo $(PENGLAI_SDK)
	$(CC) $(CFLAGS) -c $<

$(APP_BIN): % : %.o $(SDK_EAPP_LIB) $(SDK_GM_LIB) $(MUSL_LIBC) $(GCC_LIB)
	$(LINK) $(LDFLAGS) -o $@ $^ -T $(APP_LDS)
	chmod -x $@

clean:
	rm -f *.o $(APP_BIN)
