#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>

const char *code = "\x48\xB8\x48\x61\x43\x6B\x65\x44\x0A\x03\x50\x48\x8D\x34\x24\xB8\x01\x00\x00\x00\xBF\x01\x00\x00\x00\xBA\x07\x00\x00\x00\x0F\x05";
const char code2[] = {0x48,0xB8,0x48,0x61,0x43,0x6B,0x65,0x44,0x0A,0x03,0x50,
						0x48,0x8D,0x34,0x24,0xB8,0x01,0x00,0x00,0x00,0xBF,0x01,
						0x00,0x00,0x00,0xBA,0x07,0x00,0x00,0x00,0x0F,0x05};

int codeLen = 32;

int		main(int argc, char **argv) {
	int		fd = open("target", O_RDWR);
	char	buffer[1000];
	int		structNum = 0;
	int		secOffset = 0;
	// ENTRY HEADER
	Elf64_Ehdr *Ehdr = NULL;
	// PROGRAM SEGMENT HEADER
	Elf64_Phdr *Phdr = NULL;
	Elf64_Shdr *Shdr = NULL;

	read(fd, buffer, sizeof(Elf64_Ehdr));
	Ehdr = (Elf64_Ehdr *)buffer;
	structNum = Ehdr->e_phnum;

	// PARSE SEGMENTS
	lseek(fd, Ehdr->e_phoff, SEEK_SET);
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
			// TRIES TO INJECT CODE
			printf("Writing at address: %lx\n", Phdr->p_vaddr);
			lseek(fd, Phdr->p_vaddr, SEEK_SET);
			int j = 0;
			while (j < 32) {
				write(fd, &code2[j], 1);
				j++;
			}
			printf("Injected %d hex values\n", j);
			i = 300;
		}
		if (Phdr->p_type == 1 && Phdr->p_flags == 6) {
			printf("Found data segment at offset: 0x%lx\n", Phdr->p_offset);
			printf("End of data segment: 0x%x\n", Phdr->p_vaddr + Phdr->p_filesz);
			// INJECT CODE AT END DATA SEGMENT
			
		}
		i++;
	}
	close(fd);
	return 1;
}
