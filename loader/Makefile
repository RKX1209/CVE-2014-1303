CC		:=	gcc
AS		:=	gcc
OBJCOPY	:=	objcopy
CFLAGS	:=	-O2 -std=c11 -fno-builtin -nostartfiles -nostdlib -masm=intel -m64 -mabi=sysv -mcmodel=large -fno-asynchronous-unwind-tables -fPIE -pie
SFLAGS	:=	-nostartfiles -nostdlib -fno-asynchronous-unwind-tables -fPIE -pie
LFLAGS	:=	$(LDIRS) -T linker.ld -Wl,--build-id=none -fno-asynchronous-unwind-tables -fPIE -pie
CFILES	:=	$(wildcard *.c)
SFILES	:=	$(wildcard *.s)
OBJS	:=	$(patsubst %.c, %.o, $(CFILES)) $(patsubst %.s, %.o, $(SFILES))

TARGET = $(shell basename $(CURDIR)).bin

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LFLAGS) -o temp.t *.o
	$(OBJCOPY) -O binary temp.t $(TARGET)
	$(CC) -o bin2js.elf bin2js/bin2js.c
	#rm -f temp.t

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

%.o: %.s
	$(AS) -c -o $@ $< $(SFLAGS)

.PHONY: clean

clean:
	rm -f $(TARGET) *.o *.elf *.js
