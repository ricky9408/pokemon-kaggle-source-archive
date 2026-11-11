# LaunchGateV1.S
#
# Zero-authority Stage-1 x86_64 Linux LaunchGateV1 ABI implementation.
# The authenticated page is assembled separately and is not linked into the
# supervisor. It contains one 4096-byte executable section: reachable code,
# 0xCC padding, and one authenticated NUL byte at page offset 4095.
#
# Entry: rdi = LaunchGateInputV1, rax = 0 on a successful parent return.
# The only register retained across syscalls is r9, which holds the input
# record pointer. The child never reaches ret and performs no memory writes.
#
# LaunchGateInputV1, 64 bytes:
#   +0  abi_version       u64 = 1
#   +8  record_size       u64 = 64
#   +16 result_ptr        u64, nonzero and 8-byte aligned
#   +24 clone_args_ptr    u64, nonzero and 8-byte aligned
#   +32 exec_fd           u64, 5..INT32_MAX
#   +40 argv_ptr           u64, nonzero and 8-byte aligned
#   +48 envp_ptr           u64, nonzero and 8-byte aligned
#   +56 reserved          u64 = 0
#
# LaunchGateResultV1, 48 bytes:
#   +0  state             u64: 0 EMPTY, 1 PREPARED_NO_CHILD,
#                              2 NO_CHILD_FAILURE, 3 CHILD_CREATED
#   +8  child_pid         s64
#   +16 pidfd             s32
#   +20 pidfd_padding     u32
#   +24 parent_pid        s64
#   +32 status            s64
#   +40 reserved          u64
#
# Fixed gate-local returns: LG_E_RECORD = -4096 and LG_E_GETPID = -4097.
#
# The three fixed ranges are [input, input+64), [result, result+48), and
# [clone_args, clone_args+88); each must be non-wrapping and pairwise
# non-overlapping. The result must be all zero before validation completes.

.section .text.launch_gate_v1,"ax",@progbits
.p2align 12
.globl launch_gate_v1
.type launch_gate_v1,@function
launch_gate_v1:
    endbr64

    # The input record itself must be a non-wrapping, 8-byte-aligned range.
    testq   %rdi, %rdi
    jz      .Lrecord_failure_preinit
    testq   $7, %rdi
    jnz     .Lrecord_failure_preinit
    leaq    64(%rdi), %rax
    cmpq    %rdi, %rax
    jbe     .Lrecord_failure_preinit

    # r9 is the only persistent register across the syscall sequence.
    movq    %rdi, %r9
    movq    16(%r9), %r8
    movq    24(%r9), %r10

    # Validate the exact input ABI and pointer alignment.
    cmpq    $1, 0(%r9)
    jne     .Lrecord_failure_preinit
    cmpq    $64, 8(%r9)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 56(%r9)
    jne     .Lrecord_failure_preinit
    testq   %r8, %r8
    jz      .Lrecord_failure_preinit
    testq   $7, %r8
    jnz     .Lrecord_failure_preinit
    testq   %r10, %r10
    jz      .Lrecord_failure_preinit
    testq   $7, %r10
    jnz     .Lrecord_failure_preinit
    movq    40(%r9), %rax
    testq   %rax, %rax
    jz      .Lrecord_failure_preinit
    testq   $7, %rax
    jnz     .Lrecord_failure_preinit
    movq    48(%r9), %rax
    testq   %rax, %rax
    jz      .Lrecord_failure_preinit
    testq   $7, %rax
    jnz     .Lrecord_failure_preinit
    cmpq    $5, 32(%r9)
    jb      .Lrecord_failure_preinit
    cmpq    $0x7fffffff, 32(%r9)
    ja      .Lrecord_failure_preinit

    # Validate non-wrapping result and clone_args ranges, then their overlap.
    leaq    64(%r9), %r11
    leaq    48(%r8), %rax
    cmpq    %r8, %rax
    jbe     .Lrecord_failure_preinit
    leaq    88(%r10), %rdx
    cmpq    %r10, %rdx
    jbe     .Lrecord_failure_preinit
    cmpq    %r8, %r11
    jbe     .Linput_result_disjoint
    cmpq    %r9, %rax
    jbe     .Linput_result_disjoint
    jmp     .Lrecord_failure_preinit
.Linput_result_disjoint:
    cmpq    %r10, %r11
    jbe     .Linput_clone_disjoint
    cmpq    %r9, %rdx
    jbe     .Linput_clone_disjoint
    jmp     .Lrecord_failure_preinit
.Linput_clone_disjoint:
    cmpq    %r10, %rax
    jbe     .Lresult_clone_disjoint
    cmpq    %r8, %rdx
    jbe     .Lresult_clone_disjoint
    jmp     .Lrecord_failure_preinit
.Lresult_clone_disjoint:

    # The complete result record must be zero on entry.
    cmpq    $0, 0(%r8)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 8(%r8)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 16(%r8)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 24(%r8)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 32(%r8)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 40(%r8)
    jne     .Lrecord_failure_preinit

    # Full clone_args equality validation before result initialization.
    cmpq    $0x1000, 0(%r10)
    jne     .Lrecord_failure_preinit
    leaq    16(%r8), %rax
    cmpq    %rax, 8(%r10)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 16(%r10)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 24(%r10)
    jne     .Lrecord_failure_preinit
    cmpq    $17, 32(%r10)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 40(%r10)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 48(%r10)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 56(%r10)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 64(%r10)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 72(%r10)
    jne     .Lrecord_failure_preinit
    cmpq    $0, 80(%r10)
    jne     .Lrecord_failure_preinit

    # Initialize the exact result state before getpid and clone3.
    movq    $1, 0(%r8)
    movq    $0, 8(%r8)
    movl    $-1, 16(%r8)
    movl    $0, 20(%r8)
    movq    $0, 24(%r8)
    movq    $0, 32(%r8)
    movq    $0, 40(%r8)

    # __NR_getpid = 39; only a positive PID is accepted.
    movl    $39, %eax
    syscall
    testq   %rax, %rax
    jle     .L_getpid_failure
    movq    16(%r9), %r8
    movq    %rax, 24(%r8)

    # Duplicate the complete clone_args validation immediately before clone3.
    movq    24(%r9), %r10
    cmpq    $0x1000, 0(%r10)
    jne     .Lrecord_failure_after_init
    leaq    16(%r8), %rax
    cmpq    %rax, 8(%r10)
    jne     .Lrecord_failure_after_init
    cmpq    $0, 16(%r10)
    jne     .Lrecord_failure_after_init
    cmpq    $0, 24(%r10)
    jne     .Lrecord_failure_after_init
    cmpq    $17, 32(%r10)
    jne     .Lrecord_failure_after_init
    cmpq    $0, 40(%r10)
    jne     .Lrecord_failure_after_init
    cmpq    $0, 48(%r10)
    jne     .Lrecord_failure_after_init
    cmpq    $0, 56(%r10)
    jne     .Lrecord_failure_after_init
    cmpq    $0, 64(%r10)
    jne     .Lrecord_failure_after_init
    cmpq    $0, 72(%r10)
    jne     .Lrecord_failure_after_init
    cmpq    $0, 80(%r10)
    jne     .Lrecord_failure_after_init

    # __NR_clone3 = 435, exact 88-byte record.
    movq    %r10, %rdi
    movl    $88, %esi
    movl    $435, %eax
    syscall
    testq   %rax, %rax
    js      .L_clone_failure
    jz      .Lchild_path

    # Positive parent branch: publish child PID, status, then state last.
    movq    16(%r9), %r8
    movq    %rax, 8(%r8)
    movq    $0, 32(%r8)
    movq    $0, 40(%r8)
    movq    $3, 0(%r8)
    xorl    %eax, %eax
    jmp     .Lparent_return

.Lrecord_failure_preinit:
    movq    $-4096, %rax
    jmp     .Lparent_return

.Lrecord_failure_after_init:
    movq    $-4096, 32(%r8)
    movq    $2, 0(%r8)
    movq    $-4096, %rax
    jmp     .Lparent_return

.L_getpid_failure:
    movq    16(%r9), %r8
    movq    $-4097, 32(%r8)
    movq    $2, 0(%r8)
    movq    $-4097, %rax
    jmp     .Lparent_return

.L_clone_failure:
    movq    16(%r9), %r8
    movq    %rax, 32(%r8)
    movq    $2, 0(%r8)
    jmp     .Lparent_return

.Lparent_return:
    ret

.Lchild_path:
    # __NR_prctl = 157, PR_SET_PDEATHSIG = 1, SIGKILL = 9.
    movl    $157, %eax
    movl    $1, %edi
    movl    $9, %esi
    xorl    %edx, %edx
    xorl    %r10d, %r10d
    xorl    %r8d, %r8d
    syscall
    testq   %rax, %rax
    jne     .Lchild_exit_127

    # Reload all non-r9 state from the validated inherited records.
    movl    $110, %eax
    syscall
    testq   %rax, %rax
    jle     .Lchild_exit_127
    movq    16(%r9), %r8
    cmpq    24(%r8), %rax
    jne     .Lchild_exit_127

    # __NR_execveat = 322; pathname is the authenticated page byte at +4095.
    movq    32(%r9), %rdi
    leaq    .Lempty_path(%rip), %rsi
    movq    40(%r9), %rdx
    movq    48(%r9), %r10
    movl    $0x1000, %r8d
    movl    $322, %eax
    syscall

.Lchild_exit_127:
    # __NR_exit_group = 231, status 127; retry forever if it returns.
    movl    $231, %eax
    movl    $127, %edi
    syscall
    jmp     .Lchild_exit_127

.Lcode_end:
.size launch_gate_v1, .Lcode_end-launch_gate_v1

# The remaining page bytes are authenticated trap padding, followed by the
# only pathname byte accepted by execveat(AT_EMPTY_PATH).
.fill 4095-(.-launch_gate_v1), 1, 0xcc
.Lempty_path:
.byte 0x00

.section .note.GNU-stack,"",@progbits
