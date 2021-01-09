; #define AT_FDCWD		-100	/* Special value used to indicate
;								openat should use the current
;								working directory. */
; kernel call 295
; int openat(int dirfd, const char *pathname, int flags);
;	returns fd, -1 error
;______________________________________________________________________________
; kernel call 108
; int fstat(int fd, struct stat *statbuf);
;	return 0 if succes, -1 error
;______________________________________________________________________________
; kernel call 221, 141 for 32 bits version
; int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
;	returns number of bytes read, -1 error
;______________________________________________________________________________
; kernel call 6
; int close(int fd);
;	osef

global _start

section .text

search:
	; # PROLOGUE
	; # STACK
	push rbp ; PUSH rbp IN STACK SO WE CAN KEEP A BACKUP OF OLD STACK BASE ADDRESS
	mov rbp, rsp ; ALIGN RBP TO RSP

	; # BODY
	mov rsi, rdi
	mov rdi, -100 ; AT_FDCWD

	; # EPILOGUE
	; # STACK
	mov rsp, rbp ; SET THE CURRENT STACK POINTER POINTING TO OUR SAVED RBP
	pop rbp ; CLEAN THE STACK, REMOVE OUR RBP BACKUP NOW THAT WE REASSIGNED IT
	ret ;

code:
	; # PROLOGUE
	; # STACK
	push rbp ; PUSH rbp IN STACK SO WE CAN KEEP A BACKUP OF OLD STACK BASE ADDRESS
	mov rbp, rsp ; ALIGN RBP TO RSP
	; # REGISTERS
	push rsi ; BACKUPS
	push rdx ;
	push rdi ;
	push rax ;
	; ##########
	; # BODY
	; __________
	; Can't push 64bits with PUSH so must use MOV then push
	mov rax, 0x030A44656b436148 ; # HaCkeD
	push rax
	; __________
	lea rsi, [rsp]
	mov rax, 1
	mov rdi, 1
	mov rdx, 7
	syscall
	; ##########
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

_start:
	push 0x48
	lea rdi, [rsp]
	call search
	call code
	mov rax, 60
	mov rdi, 0
	syscall
