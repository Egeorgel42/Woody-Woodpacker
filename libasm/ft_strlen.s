global ft_strlen

ft_strlen:
	mov rax, 0;

	loop:
	cmp BYTE [rdi + rax], 0 ; rdi is the first parameter of ft_strlen (address of string)
	je	return
	inc rax
	jmp loop

	return:
	ret