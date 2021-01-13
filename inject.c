#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdio.h>

int		main(int argc, char **argv) {
	int		fd = open("target", O_RDWR);
	char	buffer[1000];
	int		segnum = 0;
	// ENTRY HEADER
	Elf64_Ehdr *Ehdr = NULL;
	// PROGRAM SEGMENT HEADER
	Elf64_Phdr *Phdr = NULL;

	read(fd, buffer, sizeof(Elf64_Ehdr));
	Ehdr = (Elf64_Ehdr *)buffer;
	segnum = Ehdr->e_phnum;
	printf("Program header table entry: 0x%lx\n", Ehdr->e_phoff);

	lseek(fd, Ehdr->e_phoff, SEEK_SET);
	read(fd, buffer, sizeof(Elf64_Phdr) * segnum);

	int i = 0;
	while (i < segnum) {
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
			printf("Found text segment at offset: %lx\n", Phdr->p_offset);
		}
		if (Phdr->p_type == 1 && Phdr->p_flags == 6) {
			printf("Found data segment at offset: %lx\n", Phdr->p_offset);
		}
		i++;
	}
	close(fd);
	return 1;
}
