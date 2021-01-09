; #define AT_FDCWD		-100	/* Special value used to indicate
;								openat should use the current
;								working directory. */
; kernel call 257
; int openat(int dirfd, const char *pathname, int flags);
;	returns fd, -1 error
;______________________________________________________________________________
; kernel call 5
; int fstat(int fd, struct stat *statbuf);
;	return 0 if succes, -1 error
;______________________________________________________________________________
; kernel call 217, 78 for 32 bits version
; int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
;	returns number of bytes read, -1 error
;______________________________________________________________________________
; kernel call 3
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
	; # OPENAT CALL, TODO: CHECK RETURN VALUE
	mov rsi, rdi ; SEARCH ARG (PATHNAME)
	mov rdi, -100 ; AT_FDCWD, start from current dir (relative path)
	mov rdx, 0x90800 ; O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY
	mov rax, 257 ; OPENAT KERNEL CODE
	syscall
	; # GETDENTS CALL
	mov rdi, rax ; FD FROM OPENAT
	mov rax, 217 ; GETDENTS64 KERNEL CODE
	sub rsp, 4096 ; ADD 1 PAGE TO THE STACK, TODO: CHECK IF CRASH WHEN FOLDER 2 BIG
				  ; LS getdents64: getdents64(3, /* 9 entries */, 32768)
				  ; BUFFER SIZE: 32768
	mov rsi, rsp ; *DIRP BUFFER ADDRESS
	mov edx, 4096 ; SPECIFY THE SIZE OF OUR BUFFER TO OPENAT
	syscall ; RETURNS NUMBER OF BYTES READ
	; # CLOSE OPENAT FD
	push rax ; BACKUP GETDENTS RET
	mov rax, 3 ; CLOSE KERNEL CODE
	syscall
	pop rax ; GET BACK OUR RAX VALUE
	; # GO PARSE OUR RET STRUCTS
	; START OF STRUCT STACK
	mov rsi, rsp ; THE START OF OUR RET STRUCT STORED IN RSI
	; END OF STRUCT STACK
	mov rdi, rsp ; STOCK RSP IN RDI SO I CAN ADD GETDENTS RET TO DETERMINE THE SIZE
	add rdi, rax ; THE END OF OUR RET STRUCT STORED IN RDI
	;
	add rsi, 10 ; D_NAME (10 BYTES)

	; #########
	mov rax, 1
	mov rdi, 1
	mov rdx, 10
	syscall
	; #########
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
	push 0x2E ; FOLDER TO PARSE '.'
	lea rdi, [rsp] ; GET POINTER STACK ADDRESS FOR OUR PATHNAME
	call search
	call code
	mov rax, 60
	mov rdi, 0
	syscall
