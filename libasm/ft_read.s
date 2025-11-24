global ft_read
extern __errno_location

ft_read:
	mov rax, 0
	syscall
	cmp rax, -4095	; check for err (between -4095 and -1)
    jae error ; check as unsigned, so -1 is technically higher than 0
	ret

error:
	neg rax
	push rbx
	mov rbx, rax
	call __errno_location wrt ..plt
	mov [rax], rbx
	pop rbx
	mov rax, -1
	ret