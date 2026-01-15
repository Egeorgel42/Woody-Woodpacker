; -----------------------------------------------------------------------------
; GLOBAL PAYLOAD
; -----------------------------------------------------------------------------

section .text
	global _start

_start:
	; Save Context (original program state)
	pushfq
	push rax
	push rbx
	push rcx
	push rdx
	push r8
	push r9
	push r10
	push r11
	push r12
	push rsi
	push rdi

	; Print WOODY Message (Write syscall)
	mov rax, 1                  ; RAX = 1 (syscall write)
	mov rdi, 1                  ; RDI = 1 (File Descriptor for STDOUT)
	lea rsi, [rel msg_woody]    ; RSI = buffer add(relative to current instruction)
	mov rdx, 14                 ; RDX = Length (13 char + 1 \n)
	syscall                     ; kernel call

	; INIT DECRYPTION
	lea rsi, [rel ckey]         ; RSI points to the key
	lea rdi, [rel start_txt]    ; RDI points to the start of ciphered zone
	
	mov r15, [rel txt_size]     ; R15 contains the txt size (We use R15 because RCX is used in XTEA)
	shr r15, 3 				    ; R15 / 8 = number of blocks to uncipher

; da big loop
.big_loop:
	; calling xtea routine
	call xtea_decrypt_block

	add rdi, 8 				; We go to next block (+8 bytes)
	dec r15 				; decrement block counter (R15)
	jnz .big_loop 			; if not done yet, start again

	; -------- Changing .text perms with mprotect syscall ------

	mov rax, 10 ; mprotect syscall number
	; Adress calculation
	mov rdi, [rel start_txt]	; addr pointing to the start of .text
	mov r9, rdi 				; save exact address for size calc

	; since mprotect is picky, we need to give it the exact page alignement
	; so we align to erase the 12 last bits (align to 4096 bytes)

	and rdi, 0xFFFFFFFFFFFFF000

	; Size calculation (size must cover from the very start calculated above
	; to its real end in .text)

	mov rsi, [rel txt_size] 	; original code size
	add rsi, r9 				; exact end address
	sub rsi, rdi 				; exact end - aligned start = total size

	; FLAGS
	mov rdx, 5 					; PROT_READ (1) | PROT_EXEC (4) = 5

	syscall 					; exec

	; 4. Restore Context (LIFO order - Inverse of Push)
	; We restore everything exactly as it was before jumping back to the host
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
	popfq

	; 5. JUMP TO ORIGINAL ENTRY POINT
	jmp [rel old_entry_point]


; -----------------------------------------------------------------------------
; XTEA Decryption Routine (x64)
; RDI = encrypted code address (v)
; RSI = encryption key address (k)
; -----------------------------------------------------------------------------
global xtea_decrypt_block

xtea_decrypt_block:

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
	

	; RET: We return to the caller (_start loop)
	; Note: Context restoration (POP) is handled in _start now
	ret

; -----------------------------------------------------------------------------
; DATA placeholders (filled by the C)
; -----------------------------------------------------------------------------
align 8
msg_woody:       db "....WOODY....", 0xA, 0
ckey:            times 16 db 0      
start_txt:       dq 0               
txt_size:        dq 0               
old_entry_point: dq 0