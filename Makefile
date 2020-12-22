# 可执行文件
TARGET = test
# 依赖目标
OBJS = test.o plthook_elf.o
 
# 指令编译器和选项
CC=gcc
CFLAGS=-Wall -std=gnu99
LDFLAGS = -L/usr/local/lib -L./confparser -lconfparser -levent -lpthread -ldl
ccflags-y := -ldl
$(TARGET):$(OBJS)
# @echo TARGET:$@
# @echo OBJECTS:$^
	$(CC) -o $@ $^ -ldl -g
 
clean:
	rm -rf $(TARGET) $(OBJS)