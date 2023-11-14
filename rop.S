.intel_syntax noprefix
.globl sysc
.macro jax a
    mov r11w, \a
    jmp smash
.endm

.macro jaxg from, to
    jax \from
    .if \to-\from
        jaxg "(\from+1)",\to
    .endif
.endm

//2 layers of macro needed to avoid exceeding macro nesting limit
.macro jaxg2 a, b
    jaxg \a, (\a+49)
    .if (\a+49)-\b
        jaxg2 (\a+50), \b
    .endif
.endm

sysc:
    jaxg2 0, 499
smash:
    mov r10, rcx
    movabs rax, rop
    mov rcx, rax
    movzx eax, r11w
    jmp rcx