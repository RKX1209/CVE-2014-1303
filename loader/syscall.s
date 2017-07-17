.text

.global syscall3
syscall3:
        movq %rdi, %rax
        movq %rsi, %rdi
        movq %rdx, %rsi
        movq %rcx, %rdx
        syscall
        retq
.global syscall2
syscall2:
        movq %rdi, %rax
        movq %rsi, %rdi
        movq %rdx, %rsi
        syscall
        retq
.global syscall1
syscall1:
        movq %rdi, %rax
        movq %rsi, %rdi
        syscall
        retq
