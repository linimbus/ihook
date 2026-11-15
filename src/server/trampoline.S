/*
 * x86-64 System V entry/exit trampoline helpers.
 *
 * A per-slot executable stub loads the slot id into %r11 and jumps here.  We
 * save all argument registers (including vector registers and the varargs
 * count in %al), call the C bookkeeping function, restore the registers, and
 * tail-jump to the original function.  In enter_exit mode the C function also
 * replaces the caller's return address with ihook_exit_stub; the exit stub
 * saves the return registers, calls C to pop its per-thread frame, restores
 * the return registers, and jumps to the real caller.
 */
    .text

    .globl ihook_common_entry
    .type ihook_common_entry, @function
ihook_common_entry:
    endbr64
    pushq %rax                  /* varargs vector count (also return slot) */
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %r11                  /* slot id */

    /* 128 bytes for xmm0..xmm7 plus 8 bytes of alignment padding. */
    subq $136, %rsp
    movdqu %xmm0, 8(%rsp)
    movdqu %xmm1, 24(%rsp)
    movdqu %xmm2, 40(%rsp)
    movdqu %xmm3, 56(%rsp)
    movdqu %xmm4, 72(%rsp)
    movdqu %xmm5, 88(%rsp)
    movdqu %xmm6, 104(%rsp)
    movdqu %xmm7, 120(%rsp)

    /* rsp + 200 is the stack slot holding the caller's return address. */
    movl %r11d, %edi
    leaq 200(%rsp), %rsi
    call ihook_on_enter

    /* Keep the original address in a scratch register; %rax is restored
       below because it carries the varargs vector count. */
    movq %rax, %r11

    movdqu 8(%rsp), %xmm0
    movdqu 24(%rsp), %xmm1
    movdqu 40(%rsp), %xmm2
    movdqu 56(%rsp), %xmm3
    movdqu 72(%rsp), %xmm4
    movdqu 88(%rsp), %xmm5
    movdqu 104(%rsp), %xmm6
    movdqu 120(%rsp), %xmm7

    addq $136, %rsp
    addq $8, %rsp               /* discard saved slot id */
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rax
    jmpq *%r11
    .size ihook_common_entry, .-ihook_common_entry

    .globl ihook_exit_stub
    .type ihook_exit_stub, @function
ihook_exit_stub:
    /* Reached by the target function's ret: rsp % 16 == 0 here.  Preserve
       the registers used for return values (integer and SSE classes). */
    subq $64, %rsp
    movq %rax, 0(%rsp)
    movq %rdx, 8(%rsp)
    movdqu %xmm0, 16(%rsp)
    movdqu %xmm1, 32(%rsp)

    call ihook_on_exit

    movq %rax, %r11
    movq 0(%rsp), %rax
    movq 8(%rsp), %rdx
    movdqu 16(%rsp), %xmm0
    movdqu 32(%rsp), %xmm1
    addq $64, %rsp
    jmpq *%r11
    .size ihook_exit_stub, .-ihook_exit_stub

    .section .note.GNU-stack,"",@progbits
