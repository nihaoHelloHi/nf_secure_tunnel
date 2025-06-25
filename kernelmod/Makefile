# 模块名（可改成你想要的名字）
MODULE_NAME	= nst

# 源文件列表（不包含路径）
SRC := \
	main_mod.c \
	src/nst_conn.c \
	src/nst_csum.c \
	src/nst_anti-rp.c \
	src/nst_log.c \
	src/nst_plhdr.c \
	src/nst_hook.c \
	src/nst_encrypt.c \
	src/nst_encrypt_algo.c \
	tool.c

# 内核源码路径（默认使用当前系统内核）
KERNELDIR := /lib/modules/$(shell uname -r)/build
# 添加头文件搜索路径
EXTRA_CFLAGS := -I$(PWD)/include
PWD := $(shell pwd)

# 把SRC中的.c转出.o
$(MODULE_NAME)-objs := $(SRC:.c=.o)
obj-m := $(MODULE_NAME).o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -rf modules.order
	rm -f *.symvers
