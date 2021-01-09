; int openat(int dirfd, const char *pathname, int flags);
;	returns fd, -1 error
; int fstat(int fd, struct stat *statbuf);
;	return 0 if succes, -1 error
; int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
;	returns number of bytes read, -1 error
; int close(int fd);
;	osef

global _start

section .text

code:
	; # PROLOGUE
	; # STACK
	push rbp ; PUSH rbp IN STACK SO WE CAN KEEP A BACKUP OF OLD STACK BASE ADDRESS
	mov rbp, rsp ; ALIGN RBP TO RSP
	; # REGISTERS
	push rsi ; BACKUPS
	push rdx ;
	push rdi
	push rax ;
	; ##########
	; Can't push 64bits with PUSH so must use MOV then push
	; # HaCkeD
	mov rax, 0x030A44656b436148 ; 1 CHAR = 1 byte,
	push rax
	; ############
	lea rsi, [rsp]
	mov rax, 1
	mov rdi, 1
	mov rdx, 7
	syscall
	; # EPILOGUE
	; # REGISTERS
	pop rax
	pop rax
	pop rdi
	pop rdx
	pop rsi
	; # STACK
	mov rsp, rbp ; SET THE CURRENT STACK POINTER POINTING TO OUR SAVED RBP
	pop rbp ; CLEAN THE STACK, REMOVE OUR RBP BACKUP NOW THAT WE REASSIGNED IT
	ret ;
	; EXIT, REMOVE AFTER

_start:
	call code
	mov rax, 60
	mov rdi, 0
	syscall
	; ##########
