global ft_strcpy

ft_strcpy:
	mov rax, rdi ; return dest
	mov rcx, 0

	loop:
	mov dl, [rsi + rcx]      ; rsi = dest && rdi = src
	mov [rdi + rcx], dl      ; dl = 1 BYTE section of register rdx, here rdx is not a function param
	cmp	BYTE [rsi + rcx], 0
	je return
	inc rcx
	jmp loop

	return:
	ret