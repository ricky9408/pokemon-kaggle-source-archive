.section .text.stage1_extraction_child_gate_v1,"ax",@progbits
.p2align 6
.globl stage1_extraction_child_gate_v1
.hidden stage1_extraction_child_gate_v1
.type stage1_extraction_child_gate_v1,@function

# Linux x86_64 raw-syscall-only Stage-1 extraction child gate.  This candidate
# ABI is private and zero-authority.  The sole parent return is at .Lparent_ret;
# the clone3 zero-return region has no path to it.
stage1_extraction_child_gate_v1:
    pushq %r12
    pushq %r13
    movq %rdi, %r12
    movq %rsi, %r13

    movq $-1, 0(%r13)
    movl $-1, 8(%r13)
    movl $-1, 12(%r13)
    movl $0, 16(%r13)
    movl $0, 20(%r13)

    movq 0(%r12), %rdi
    movq 8(%r12), %rsi
    movl $435, %eax
    syscall
    movq %rax, 0(%r13)
    testq %rax, %rax
    js .Lparent_no_child
    jz .Lchild

    movl %eax, 8(%r13)
    movl $1, 16(%r13)
    jmp .Lparent_ret

.Lparent_no_child:
    movl $2, 16(%r13)

.Lparent_ret:
    popq %r13
    popq %r12
    ret

.Lchild:
    # Close every parent-only control, ready, capture-read, receipt, and
    # diagnostic descriptor inherited across clone3.
    movslq 20(%r12), %rdi
    movl $3, %eax
    syscall
    testq %rax, %rax
    js .Lchild_fail

    movslq 24(%r12), %rdi
    movl $3, %eax
    syscall
    testq %rax, %rax
    js .Lchild_fail

    movslq 32(%r12), %rdi
    movl $3, %eax
    syscall
    testq %rax, %rax
    js .Lchild_fail

    movslq 36(%r12), %rdi
    movl $3, %eax
    syscall
    testq %rax, %rax
    js .Lchild_fail

    movslq 40(%r12), %rdi
    movl $3, %eax
    syscall
    testq %rax, %rax
    js .Lchild_fail

    movslq 44(%r12), %rdi
    movl $3, %eax
    syscall
    testq %rax, %rax
    js .Lchild_fail

    # Consume the exact parent release byte 0x47.
    movq 56(%r12), %rsi
    movb $0, (%rsi)
    movslq 16(%r12), %rdi
    movl $1, %edx
    xorl %eax, %eax
    syscall
    cmpq $1, %rax
    jne .Lchild_fail
    movq 56(%r12), %rsi
    cmpb $0x47, (%rsi)
    jne .Lchild_fail

    # Enter the retained extraction directory and reauthenticate cwd.
    movslq 48(%r12), %rdi
    movl $81, %eax
    syscall
    testq %rax, %rax
    js .Lchild_fail

    movq 64(%r12), %r8
    movq $-100, %rdi
    movq 72(%r12), %rsi
    movl $0x1000, %edx
    movl $0x17ff, %r10d
    movl $332, %eax
    syscall
    testq %rax, %rax
    js .Lchild_fail

    movq 64(%r12), %r9
    movl 0(%r9), %eax
    testl $0x1000, %eax
    jz .Lchild_fail
    movq 144(%r9), %rax
    cmpq 104(%r12), %rax
    jne .Lchild_fail
    movq 32(%r9), %rax
    cmpq 112(%r12), %rax
    jne .Lchild_fail
    movl 136(%r9), %eax
    cmpl 120(%r12), %eax
    jne .Lchild_fail
    movl 140(%r9), %eax
    cmpl 124(%r12), %eax
    jne .Lchild_fail

    # Lock privilege and cwd/process mutation before announcing readiness.
    movl $38, %edi
    movl $1, %esi
    xorl %edx, %edx
    xorl %r10d, %r10d
    xorl %r8d, %r8d
    movl $157, %eax
    syscall
    testq %rax, %rax
    js .Lchild_fail

    movl $1, %edi
    xorl %esi, %esi
    movq 80(%r12), %rdx
    movl $317, %eax
    syscall
    testq %rax, %rax
    js .Lchild_fail

    movq 56(%r12), %rsi
    movb $0x52, (%rsi)
    movslq 28(%r12), %rdi
    movl $1, %edx
    movl $1, %eax
    syscall
    cmpq $1, %rax
    jne .Lchild_fail

    # The ready-barrier candidate blocks here because PID 1 withholds 0x43.
    movq 56(%r12), %rsi
    movb $0, (%rsi)
    movslq 16(%r12), %rdi
    movl $1, %edx
    xorl %eax, %eax
    syscall
    cmpq $1, %rax
    jne .Lchild_fail
    movq 56(%r12), %rsi
    cmpb $0x43, (%rsi)
    jne .Lchild_fail

    movslq 52(%r12), %rdi
    movq 72(%r12), %rsi
    movq 88(%r12), %rdx
    movq 96(%r12), %r10
    movl $0x1000, %r8d
    movl $322, %eax
    syscall

.Lchild_fail:
    movl $127, %edi
    movl $231, %eax
    syscall
    ud2

.size stage1_extraction_child_gate_v1, .-stage1_extraction_child_gate_v1
.section .note.GNU-stack,"",@progbits
