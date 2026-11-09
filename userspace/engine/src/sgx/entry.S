/* SPDX-License-Identifier: GPL-2.0-only */
/* Windows x64 enclave entry and host-state restoration; offsets asserted in Rust.
 * AEX cancellation returns normally through the trusted host save frame;
 * no signal longjmp, Rust unwinding, or attempted reuse of an aborted TCS. */
.text
.globl milanl_enclave_enter
.hidden milanl_enclave_enter
.type milanl_enclave_enter,@function
milanl_enclave_enter:
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
    movq %rdi, %rbx
    movq %rsi, %rdi
    movq %rdx, %rsi
    leaq milanl_enclave_aep(%rip), %rcx
    movl $2, %eax
.globl milanl_enclave_eenter_instruction
.hidden milanl_enclave_eenter_instruction
milanl_enclave_eenter_instruction:
    enclu
    jmp milanl_enclave_returned
.globl milanl_enclave_aep
.hidden milanl_enclave_aep
milanl_enclave_aep:
    cld
    movq MILANL_ENCLAVE_CONTEXT(%rip), %r11
    movq %rsp, 16(%r11)
    movq 0(%r11), %rsp
    fxrstor64 32(%r11)
    /* Saved host RSP is 16-byte aligned. Only this trusted stack runs Rust. */
    call milanl_enclave_aex_check
    movq MILANL_ENCLAVE_CONTEXT(%rip), %r11
    movq 16(%r11), %rsp
    testl %eax, %eax
    jne milanl_enclave_abort
    leaq milanl_enclave_aep(%rip), %rcx
    movl $3, %eax
.globl milanl_enclave_eresume_instruction
.hidden milanl_enclave_eresume_instruction
milanl_enclave_eresume_instruction:
    enclu
    /* Successful ERESUME cannot fall through. Return failure rather than
     * raising an unrelated UD2 fault if the instruction does return. */
    jmp milanl_enclave_abort
.globl milanl_enclave_abort
.hidden milanl_enclave_abort
milanl_enclave_abort:
    movq $-1, %rdi
    movq $-1, %rsi
.globl milanl_enclave_returned
.hidden milanl_enclave_returned
milanl_enclave_returned:
    cld
    movq MILANL_ENCLAVE_CONTEXT(%rip), %r11
    fxrstor64 32(%r11)
    movq 0(%r11), %rsp
    movq (%rsp), %rdx
    movq %rdi, (%rdx)
    movq %rsi, 8(%rdx)
    addq $8, %rsp
    movq %rsi, %rax
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
.size milanl_enclave_enter, .-milanl_enclave_enter
.section .note.GNU-stack,"",@progbits
