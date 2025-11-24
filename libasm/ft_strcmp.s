global ft_strcmp

ft_strcmp:
	mov rcx, 0

	loop:
	mov dl, [rsi + rcx] ; rdi = str1 && rsi = str2
	cmp BYTE [rdi + rcx], dl ; cmp with dl (BYTE size section of rdx) to catch specific BYTE address to return
	jne return
	cmp BYTE [rdi + rcx], 0
	je return
	inc rcx
	jmp loop

	return:
	mov dl, [rdi + rcx]
	sub dl, [rsi + rcx]
	movsx rax, dl
	ret