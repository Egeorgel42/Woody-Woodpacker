#include "woody.h"

void	parse_e_ident(unsigned char *e_ident)
{
	error_if(e_ident[EI_DATA] == ELFDATA2MSB, ERR_ENDIAN); //big endian
	error_if(e_ident[EI_DATA] == ELFDATANONE || e_ident[EI_DATA] != ELFDATA2LSB, ERR_ELFHDR);
	error_if(e_ident[EI_VERSION] == EV_NONE || e_ident[EI_VERSION] != EV_CURRENT, ERR_ELFHDR);
	error_if(e_ident[EI_ABIVERSION] != 0, ERR_ELFHDR);
}

parsing_info	parse_elf(int fd)
{
	unsigned char e_ident[EI_NIDENT];

	read_safe(fd, e_ident, EI_NIDENT);
	error_if(ft_memcmp(e_ident, ELFMAG, SELFMAG) != 0, ERR_NELF);

	parse_e_ident(e_ident);
	seek_safe(fd, 0);

	switch (e_ident[EI_CLASS]) {
		case ELFCLASS32: return (parse_elf32(fd));
		case ELFCLASS64: return (parse_elf64(fd));
		default: error(ERR_NELF);
	}
}