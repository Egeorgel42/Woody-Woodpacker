; -----------------------------------------------------------------------------
; XTEA Decryption Routine (32 bits)
; EDI = encrypted code address (v)
; ESI = encryption key address (k)
; -----------------------------------------------------------------------------

global xtea_decrypt_block_32

xtea_decrypt_block_32:
	; Save context
	pushfd						; Save EFLAGS
	pushad						; Save common use registers (EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI)

	; Setup variables
	; v0 in EAX, v1 in EBX
	mov eax, [edi]
	mov ebx, [edi + 4]

	; Setup XTEA Constants
	mov ebp, 0xC6EF3720 ; sum = delta * 32 (Starting value)

	; for 32 bits we use the stack to store counter since we cant use more registers
	push 32

.loop_start:
	; ---------- Part 1 - Decrypt v1 ----------
	; Formula: v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3])

	; Calc Right term (sum + key[(sum >> 11) & 3])
	mov ecx, ebp 				; Copy 'sum'
	shr ecx, 11					; sum >> 11
	and ecx, 3 					; & 3 (index)

	mov edx, [esi + ecx*4] 		; retrieve key part (base + index*4)
	add edx, ebp 				; edx = sum + key_part (Right term stored in edx)

	; Calc Left term (((v0 << 4) ^ (v0 >> 5)) + v0)
	mov ecx, eax 				; Copy v0
	shl ecx, 4					; v0 >> 5
	
	; We need a temporary register for (v0 >> 5), so we use the stack to save edx
	push edx 					; save edx temporarily

	mov edx, eax 				; Copy v0
	shr edx, 5					; v0 >> 5
	xor ecx, edx 				; (v0 << 4) ^ (v0 >> 5)
	add ecx, eax 				; add original v0

	pop edx 					; Restore right term into edx

	; Finalize v1
	xor ecx, edx 				; left ^ right
	sub ebx, ecx 				; v1 -= result

	; ---------- Part 2 - Update sum ----------
	; Formula: sum -= delta
	sub ebp, 0x9E3779B9			; sum -= delta (using direct delta to save a register)

	; ---------- Part 3 - Decrypt v0 ----------
	; Formula: v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3])

	; Calculate Right term: (sum + key[sum & 3])
	mov ecx, ebp 				; Copy sum
	and ecx, 3 					; sum & 3

	mov edx, [esi + ecx*4] 		; retrieve key part
	add edx, ebp 				; right term in edx

	; Calculate Left term: (((v1 << 4) ^ (v1 >> 5)) + v1)
	mov ecx, ebx 				; Copy v1
	shl ecx, 4 					; v1 << 4
	
	push edx 					; save right term

	mov edx, ebx 				; Copy v1
	shr edx, 5					; v1 >> 5
	xor ecx, edx 				; (v1 << 4) ^ (v1 >> 5)
	add ecx, ebx 				; add original v1

	pop edx 					; Restore right term

	; Finalize v0
	xor ecx, edx 				; Left ^ Right
	sub eax, ecx 				; v0 -= result

	; ---------- Loop management ----------
	dec dword [esp] 			; Decrement the counter on the top of the stack
	jnz .loop_start				; if not zero, jump back to start

	; Cleanup stack
	add esp, 4

	; Store results
	mov [edi], eax          ; Write v0
    mov [edi + 4], ebx      ; Write v1

    ; Restore context
    popad 					; Restore all general registers
    popfd					; Restore flags
    ret