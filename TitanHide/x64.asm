.code

unlockCR0 proc
    mov rax, cr0
    and rax, 0FFFFFFFFFFFEFFFFh ;~10000
    mov cr0, rax
    ret
unlockCR0 endp

lockCR0 proc
    mov rax, cr0
    or rax, 10000h
    mov cr0, rax
    ret
lockCR0 endp

end