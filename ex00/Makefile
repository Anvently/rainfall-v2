ASM = payload.asm
OBJ = shellcode.o
ELF = shellcode
BIN = shellcode.bin
TEST = main.c
OUT = a.out

all: $(BIN) $(OUT)
	xxd -i $(BIN)

$(ELF): $(ASM)
	nasm -f elf64 $(ASM) -o $(OBJ)
	ld -m elf_x86_64 $(OBJ) -o $(ELF)
	rm -f $(OBJ)

$(BIN): $(ELF)
	objcopy -O binary -j .text $(ELF) $(BIN)

$(OUT): $(TEST)
	gcc $(TEST) -z execstack -no-pie -o $(OUT)

clean:
	rm -f $(OBJ) $(ELF) $(BIN) $(OUT) *.bin

.PHONY: all clean