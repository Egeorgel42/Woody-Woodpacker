#include "woody.h"

off_t get_file_size(int fd)
{
	off_t	size;

	size = lseek(fd, 0, SEEK_END);
	error_if(size < 0, ERR_LSEEK, strerror(errno));
	error_if(lseek(fd, 0, SEEK_SET) < 0, ERR_LSEEK, strerror(errno));
	return size;
}

void	parse_e_indent(unsigned char *e_ident)
{
	error_if(e_ident[EI_DATA] == ELFDATA2MSB, ERR_ENDIAN); //big endian
	error_if(e_ident[EI_DATA] == ELFDATANONE || e_ident[EI_DATA] != ELFDATA2LSB, ERR_ELFHDR);
	error_if(e_ident[EI_VERSION] == EV_NONE || e_ident[EI_VERSION] != EV_CURRENT, ERR_ELFHDR);
	error_if(e_ident[EI_ABIVERSION] != 0, ERR_ELFHDR);
}

parsing_info	parse_elf(int fd)
{
	unsigned char	e_ident[EI_NIDENT];
	unsigned char	check_ver[5] = {0x7F, 'E', 'L', 'F', 1}; //elf file always starts with 0x7F, E, L, F, last byte corresponds to 64 or 32

	ssize_t rd = read(fd, e_ident, EI_NIDENT);
	error_if(rd < EI_NIDENT, ERR_READ, strerror(errno));

	error_if(ft_strncmp((char *)e_ident, (char *)check_ver, 4), ERR_ELFHDR);

	parse_e_indent(e_ident);
	lseek(fd, 0, SEEK_SET); //set read back to the start of file

	if (!ft_strncmp((char *)e_ident, (char *)check_ver, 5)) {
		return parse_elf32(fd);
	}
	check_ver[4] = 2; //check for 64
	if (!ft_strncmp((char *)e_ident, (char *)check_ver, 5)) {
		return parse_elf64(fd);
	}

	error(ERR_NELF);
	parsing_info null;
	null.is_64 = false;
	return null;
}