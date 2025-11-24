#include "woody.h"

void	parse_elf64(int fd, unsigned char *e_indent)
{
	(void)fd;
	(void)e_indent;

	printf("64 executable");
}

void	parse_elf32(int fd, unsigned char *e_indent)
{
	(void)fd;
	(void)e_indent;
	printf("32 executable");
}


void	parse_elf(int fd, char **err_msg)
{
	unsigned char	e_ident[EI_NIDENT];
	unsigned char	check_ver[5] = {0x7F, 'E', 'L', 'F', 1};

	ssize_t rd = read(fd, e_ident, EI_NIDENT);
	if (rd < EI_NIDENT)
		vprintf_exit(err_msg[ERR_READ], strerror(errno));

	if (!ft_strncmp((char *)e_ident, (char *)check_ver, 5))
		parse_elf32(fd, e_ident);
	
	check_ver[4] = 2;
	if (!ft_strncmp((char *)e_ident, (char *)check_ver, 5))
		parse_elf64(fd, e_ident);
}