global ft_strdup
extern __errno_location
extern malloc

ft_strdup:
	push rbx    ; rbx is a "caller-save register" which means it shouldn't be overwriten, so we save the value on the stack to use it.
	mov rbx, -1

loop:
	inc rbx
	cmp BYTE [rdi + rbx], 0 ; rdi == string parameter
	jne loop

malloc_call:
	push rdi      ; save string addr to use rdi as parameter for malloc
	mov rdi, rbx
	inc rdi       ; size of string + 1
	call malloc wrt ..plt
	pop rdi
	cmp rax, 0
	je err
	mov rsi, 0

copy:
	cmp rbx, rsi       ; rsi is iterator here
	jb return
	mov dl, [rdi + rsi]
	mov [rax + rsi], dl
	inc rsi
	jmp copy

return:
	pop rbx    ; return saved value of register
	ret

err:
	pop rbx
	call __errno_location wrt ..plt
	mov QWORD [rax], 12
	mov rax, 0
	ret