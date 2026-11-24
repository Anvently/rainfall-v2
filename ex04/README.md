# Level 04

8c33zqo7hytqnsx9h3nb4juf3rdjbd80


## Description

```
$ ls -l
total 28
-r--r--r-- 1 level04 level04    38 Jun  9 23:13 README
-rwsr-x--- 1 flag04  level04 16584 Jun  9 23:13 riviera
-r--r--r-- 1 level04 level04  1866 Jun  9 23:13 riviera.c
```

```
readelf -l riviera
...
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
```

Stack is not executable, so we'll need to perform a ret2libc.

## riviera.c

### No exploit from the input function

```

static void handle_input(void) {
    char tag[32];
    char msg[256];
...
    fgets(tag, 32, stdin);
...
    fgets(msg, 256, stdin);
...
}
```

### display_entry function

```
static void display_entry(unsigned int idx) {
...
    printf(log_buf[idx].tag);
...
}
```

This function
