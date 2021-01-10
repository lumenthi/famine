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
;	struct linux_dirent64 {
;		ino64_t        d_ino;    /* 64-bit inode number */ 64bits = 8 bytes
;		off64_t        d_off;    /* 64-bit offset to next structure */ 8 bytes
;		unsigned short d_reclen; /* Size of this dirent */ 2 bytes
;		unsigned char  d_type;   /* File type */ 1 bytes
;		----------- D_NAME START 19 BYTES FROM START --------------------
;		char           d_name[]; /* Filename (null-terminated) */
;};
;______________________________________________________________________________
; kernel call 3
; int close(int fd);
;	osef

global _start

section .text

open_file:
	; # PROLOGUE
	; # STACK
	push rbp ; PUSH rbp IN STACK SO WE CAN KEEP A BACKUP OF OLD STACK BASE ADDRESS
	mov rbp, rsp ; ALIGN RBP TO RSP

	; # BODY
	; # OPEN
	mov rax, 2 ; OPEN KERNEL CODE
	mov rdi, rdx ; PATHNAME
	mov rsi, 0 ; O_RDONLY
	syscall
	; # CLOSE
	mov rdi, rax
	mov rax, 3
	syscall

	; # EPILOGUE
	; # STACK
	mov rsp, rbp ; SET THE CURRENT STACK POINTER POINTING TO OUR SAVED RBP
	pop rbp ; CLEAN THE STACK, REMOVE OUR RBP BACKUP NOW THAT WE REASSIGNED IT
	ret ;


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
	mov rdi, rsp ; THE START OF OUR RET STRUCT STORED IN RDI
	; END OF STRUCT STACK
	mov rsi, rsp ; STOCK RSP IN RDI SO I CAN ADD GETDENTS RET TO DETERMINE THE SIZE
	add rsi, rax ; THE END OF OUR RET STRUCT STORED IN RSI

parse_dir:
	; ### VALUES ###
	; RDI = START OF CURRENT STRUCT
	; RSI = END
	; RCX = D_RECLEN OF CURRENT STRUCT
	; RDX = D_NAME OF CURRENT STRUCT
	; GET RECLEN
	mov rcx, 0
	mov cx, word[rdi + 16] ; OMFG FINALLY GOT IT
	; GET D_NAME
	lea rdx, [rdi + 19]
	push rdi
	push rsi
	push rcx
	push rdx
	call open_file
	pop rdx
	pop rcx
	pop rsi
	pop rdi
	; LOOP INSTRUCTIONS
	add rdi, rcx ; MOVING OUR CURRENT STRUCT TO THE NEXT ONE BY ADDING RECLEN
	cmp qword[rdx - 8], 0x00 ; CHECK IF OFFSET TO NEXT STRUCT IS NULL
	jne parse_dir ; IF NOT NULL KEEP LOOPING
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
	; #### DEBUG_PRINT #####
	push rsi
	push rax
	push rdi
	push rdx
	push rcx
	mov rsi, rdx
	mov rax, 1
	mov rdi, 1
	mov rdx, 7
	syscall
	pop rcx
	pop rdx
	pop rdi
	pop rax
	pop rsi
	; ####################
