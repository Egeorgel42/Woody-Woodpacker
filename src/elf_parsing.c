#include "woody.h"

void	parse_e_indent(unsigned char *e_ident, char **err_msg)
{
	if (e_ident[EI_DATA] == ELFDATA2MSB) //big endian
		vprintf_exit(err_msg[ERR_ENDIAN]);
	else if (e_ident[EI_DATA] == ELFDATANONE || e_ident[EI_DATA] != ELFDATA2LSB) //?endian
		vprintf_exit(err_msg[ERR_ELFHDR]);
	if (e_ident[EI_VERSION] == EV_NONE || e_ident[EI_VERSION] != EV_CURRENT)
		vprintf_exit(err_msg[ERR_ELFHDR]);
	if (e_ident[EI_ABIVERSION] != 0)
		vprintf_exit(err_msg[ERR_ELFHDR]);
}

void	parse_elf(int fd, char **err_msg)
{
	unsigned char	e_ident[EI_NIDENT];
	unsigned char	check_ver[5] = {0x7F, 'E', 'L', 'F', 1}; //elf file always starts with 0x7F, E, L, F, last byte corresponds to 64 or 32

	ssize_t rd = read(fd, e_ident, EI_NIDENT);
	if (rd < EI_NIDENT)
		vprintf_exit(err_msg[ERR_READ], strerror(errno));

	if (ft_strncmp((char *)e_ident, (char *)check_ver, 4))
		vprintf_exit(err_msg[ERR_ELFHDR]);

	parse_e_indent(e_ident, err_msg);
	lseek(fd, 0, SEEK_SET); //set read back to the start of file

	if (!ft_strncmp((char *)e_ident, (char *)check_ver, 5))
	{
		parse_elf32(fd, err_msg);
		return;
	}
	
	check_ver[4] = 2; //check for 64
	if (!ft_strncmp((char *)e_ident, (char *)check_ver, 5))
	{
		parse_elf64(fd, err_msg);
		return;
	}
	vprintf_exit(err_msg[ERR_NELF]);
}