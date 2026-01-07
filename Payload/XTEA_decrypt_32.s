; -----------------------------------------------------------------------------
; GLOBAL PAYLOAD (32 bits)
; -----------------------------------------------------------------------------

bits 32

section .text
	global _start

_start:
	; Save Context
	; In 32-bit, pushad saves EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI all at once
	pushfd
	pushad

	; DELTA OFFSET TECHNIQUE (Position Independent Code)

	; In 32-bit, we cannot use [rel msg_woody].
	; We must find our current address in memory to calculate
	; the relative addresses of our variables.
	call .get_eip

.get_eip:
	pop ebp					; EBP now contains the execution address of .get_eip
	sub ebp, .get_eip		; EBP = 0 (base offset for relative calculations)
	
	; Now, to access a variable, we use:
	; [ebp + (variable - .get_eip)]
	; EBP acts as our anchor.

	; Print WOODY Message (int 0x80 syscall)
	mov eax, 4              ; syscall write (4 in 32-bit)
	mov ebx, 1              ; fd stdout
	
	; Calculate message address: Base + Distance
	lea ecx, [ebp + (msg_woody - .get_eip)] 
	
	mov edx, 14             ; length
	int 0x80                ; Kernel Call

	; INIT DECRYPTION
	; ESI = Key address
	lea esi, [ebp + (ckey - .get_eip)]
	
	; EDI = Start of Ciphered Text
	; We read the value stored in start_txt
	mov edi, [ebp + (start_txt - .get_eip)]
	
	; Get text size
	mov eax, [ebp + (txt_size - .get_eip)]
	shr eax, 3              ; divide by 8 (number of blocks)
	
	; We are out of registers for the loop counter
	; We will store the block counter on the stack.
	push eax                ; Stack = [Block_Counter]

; da big loop
.big_loop:
	; Call xtea routine
	call xtea_decrypt_block_32

	add edi, 8              ; Next block (+8 bytes)
	
	; Manage counter on the stack
	dec dword [esp]         ; Decrement counter at the top of stack
	jnz .big_loop           ; If not zero, continue

	add esp, 4              ; Clean up stack (remove block counter)

	; Restore Context
	popad
	popfd

	; JUMP TO ORIGINAL ENTRY POINT
	; Read the address stored in old_entry_point and jump there
	jmp [ebp + (old_entry_point - .get_eip)]


; -----------------------------------------------------------------------------
; XTEA Decryption Routine (32 bits)
; EDI = encrypted code address (v)
; ESI = encryption key address (k)
; NOTE: pushad/popad are handled in _start, but we need to manage EBP
; -----------------------------------------------------------------------------
global xtea_decrypt_block_32

xtea_decrypt_block_32:
	; Setup variables
	; v0 in EAX, v1 in EBX
	mov eax, [edi]
	mov ebx, [edi + 4]

	; EBP is currently holding our Delta Offset from _start.
	; XTEA needs EBP for 'sum'. We MUST save EBP to preserve the offset for later.
	push ebp                ; Save Delta Offset
	
	; Setup XTEA Constants
	mov ebp, 0xC6EF3720     ; sum = delta * 32

	; Inner Loop Counter (32 rounds)
	push 32                 ; Stack = [Rounds, Delta_Offset, Block_Counter...]

.loop_start:
	; ---------- Part 1 - Decrypt v1 ----------
	
	; Calc Right term (sum + key[(sum >> 11) & 3])
	mov ecx, ebp 			; sum
	shr ecx, 11
	and ecx, 3

	; ESI is ok (points to key)
	push edx                ; Save EDX (scratch register)
	mov edx, [esi + ecx*4]
	add edx, ebp            ; Right term
	
	; Calc Left term
	mov ecx, eax            ; v0
	shl ecx, 4
	
	push ebx                ; We need a temp reg, saving EBX (v1)
	mov ebx, eax            ; v0
	shr ebx, 5
	xor ecx, ebx            ; (v0<<4)^(v0>>5)
	add ecx, eax            ; + v0
	pop ebx                 ; Restore v1
	
	; Finalize v1
	xor ecx, edx            ; Left ^ Right
	sub ebx, ecx            ; v1 -= result
	pop edx                 ; Restore EDX

	; ---------- Part 2 - Update sum ----------
	sub ebp, 0x9E3779B9     ; sum -= delta

	; ---------- Part 3 - Decrypt v0 ----------
	
	; Calc Right term
	mov ecx, ebp            ; sum
	and ecx, 3
	
	push edx                ; Save EDX
	mov edx, [esi + ecx*4]
	add edx, ebp
	
	; Calc Left term
	mov ecx, ebx            ; v1
	shl ecx, 4
	
	push eax                ; Save v0 to use as temp
	mov eax, ebx            ; v1
	shr eax, 5
	xor ecx, eax
	add ecx, ebx            ; + v1
	pop eax                 ; Restore v0
	
	; Finalize v0
	xor ecx, edx
	sub eax, ecx
	pop edx

	; ---------- Loop management ----------
	dec dword [esp]         ; Decrement rounds
	jnz .loop_start

	add esp, 4              ; Clean rounds counter
	pop ebp                 ; RESTORE DELTA OFFSET

	; Store results
	mov [edi], eax
	mov [edi + 4], ebx

	ret

; -----------------------------------------------------------------------------
; DATA placeholders (32 bits = dd, not dq)
; -----------------------------------------------------------------------------
align 4
msg_woody:       db "....WOODY....", 0xA, 0
ckey:            times 16 db 0      
start_txt:       dd 0      ; dd = 4 bytes (32 bits address)         
txt_size:        dd 0      ; dd = 4 bytes         
old_entry_point: dd 0      ; dd = 4 bytes