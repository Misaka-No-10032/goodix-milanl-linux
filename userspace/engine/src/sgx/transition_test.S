/* SPDX-License-Identifier: GPL-2.0-only */
/* Test-only synthetic AEX. Contains no ENCLU or enclave/sensor access. */
.text
.globl milanl_enclave_test_aex
.hidden milanl_enclave_test_aex
.type milanl_enclave_test_aex,@function
milanl_enclave_test_aex:
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $24, %rsp
    movq %rdi, 0(%rsp)
    movq %rsi, 8(%rsp)
    fxsave64 0(%rsi)
    movq $0x11, %rbx
    movq $0x22, %rbp
    movq $0x33, %r12
    movq $0x44, %r13
    movq $0x55, %r14
    movq $0x66, %r15
    movq 0(%rsp), %rcx
    call .Lsynthetic_aex
    movq 8(%rsp), %r11
    fxsave64 512(%r11)
    xorl %eax, %eax
    cmpq $0x11, %rbx
    jne .Lbad_register
    cmpq $0x22, %rbp
    jne .Lbad_register
    cmpq $0x33, %r12
    jne .Lbad_register
    cmpq $0x44, %r13
    jne .Lbad_register
    cmpq $0x55, %r14
    jne .Lbad_register
    cmpq $0x66, %r15
    jne .Lbad_register
    jmp .Ltest_done
.Lbad_register:
    movl $1, %eax
.Ltest_done:
    addq $24, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
.Lsynthetic_aex:
    /* Use the enclave entry's trusted save frame and shared AEP/return path. */
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rcx
    movq MILANL_ENCLAVE_CONTEXT(%rip), %r11
    movq %rsp, 0(%r11)
    fxsave64 32(%r11)
    movq 8(%r11), %rsp
    xorq %rbx, %rbx
    xorq %rbp, %rbp
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15
    pxor %xmm0, %xmm0
    pxor %xmm15, %xmm15
    jmp milanl_enclave_aep
.size milanl_enclave_test_aex, .-milanl_enclave_test_aex
.section .note.GNU-stack,"",@progbits
