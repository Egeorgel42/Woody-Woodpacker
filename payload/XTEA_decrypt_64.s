; -----------------------------------------------------------------------------
; XTEA Decryption Routine (x64)
; RDI = encrypted code address (v)
; RSI = encryption key address (k)
; -----------------------------------------------------------------------------

global xtea_decrypt_block

xtea_decrypt_block:
	; Save Context (original program state)
	pushfq                  ; Save EFLAGS (condition codes: Zero Flag, etc..)
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r9
	push r10
	push r11
	push r12                ; Using r12 as a temporary register
	push rsi                ; We need rsi for Key addressing
	push rdi                ; We need rdi for Data addressing

	; Setup variables
	; v0 is stored in EAX, v1 in EBX (We use 32bits registers since XTEA is working on 32bits packages)
	mov eax, [rdi]			; Load v0 (first 4 bytes)
	mov ebx, [rdi + 4]		; Load v1 (next 4 bytes)

	; Setup XTEA Constants
	mov ecx, 0xC6EF3720		; sum = delta * 32 (Starting value for decrypt)
	mov edx, 0x9E3779B9		; og delta

	mov r8, 32				; loop counter (32 rounds)

.loop_start:
	; ---------- Part 1 - Decrypt v1 ----------
	; Formula: v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3])

	; Calculate Right term: (sum + key[(sum >> 11) & 3])
	mov r9d, ecx	; Copy 'sum' to r9d
	shr r9d, 11		; sum >> 11
	and r9d, 3		; & 3 (results in index 0, 1, 2 or 3)

	; Retrieve the key part from memory using the index
	; [rsi + r9 * 4] -> base address of key + (index * 4 bytes)
	mov r10d, [rsi + r9 * 4]
	add r10d, ecx	; r10d = sum + key_part (right term)

	; Calculate Left term: (((v0 << 4) ^ (v0 >> 5)) + v0)
	mov r11d, eax 			; Copy v0
	shl r11d, 4             ; v0 << 4
    mov r12d, eax           ; Copy v0 again
    shr r12d, 5             ; v0 >> 5
    xor r11d, r12d          ; (v0 << 4) ^ (v0 >> 5)
    add r11d, eax           ; Add original v0 -> This is the Left Term

    ; Finalize v1
    xor r11d, r10d			; left term XOR right term
    sub ebx, r11d			; v1 -= Result

	; ---------- Part 2 - Update sum ----------
	; Formula: sum -= delta
	sub ecx, edx			; sum -= delta

	; ---------- Part 3 - Decrypt v0 ----------
	; Formula: v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3])

	; Calculate Right term: (sum + key[sum & 3])
	mov r9d, ecx			; Copy 'sum'
	and r9d, 3				; sum & 3 (Index 0, 1, 2, or 3)
	mov r10d, [rsi + r9 * 4]; Retrieve key part
	add r10d, ecx			; Right term ready

	; Calculate Left term: (((v1 << 4) ^ (v1 >> 5)) + v1)
	mov r11d, ebx 			; Copy v1
	shl r11d, 4				; v1 << 4
	mov r12d, ebx 			; Copy v1 again
	shr r12d, 5				; v1 >> 5
	xor r11d, r12d			; (v1 << 4) ^ (v1 >> 5)
	add r11d, ebx 			; Add original v1 -> left term ready

	; Finalize v0
	xor r11d, r10d			; Left term ^ Right term
	sub eax, r11d 			; v0 -= Result

	; ---------- Loop management ----------

	dec r8 					; Decrement counter
	jnz .loop_start			; if r8 is not zero, jump back to start

	; Store results
	mov [rdi], eax 			; write decrypted v0 back to memory
	mov [rdi + 4], ebx 		; write decrypted v1 back to memory
	
	; Restore context (last in, first out)
	pop rdi
	pop rsi
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq                   ; Restore flags
    ret