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



## The exploit
