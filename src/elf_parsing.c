#include "woody.h"

void	parse_e_indent(unsigned char *e_ident, char **err_msg)
{
	if (e_ident[EI_DATA] == ELFDATA2MSB)
		vprintf_exit(err_msg[ERR_ENDIAN]);
	else if (e_ident[EI_DATA] == ELFDATANONE || e_ident[EI_DATA] != ELFDATA2LSB)
		vprintf_exit(err_msg[ERR_ELFHDR]);
	if (e_ident[EI_VERSION] == EV_NONE || e_ident[EI_VERSION] != EV_CURRENT)
		vprintf_exit(err_msg[ERR_ELFHDR]);
	if (e_ident[EI_ABIVERSION] != 0)
		vprintf_exit(err_msg[ERR_ELFHDR]);
}

void	parse_elf64(int fd, char **err_msg)
{
	printf("64 executable\n");
	Elf64_Ehdr	header;
	ssize_t rd = read(fd, &header, sizeof(Elf64_Ehdr));
	if (header.e_type != ET_NONE)
		vprintf_exit(err_msg[ERR_NEXEC]);

}

void	parse_elf32(int fd, char **err_msg)
{
	printf("32 executable\n");
	Elf32_Ehdr	header;
	ssize_t rd = read(fd, &header, sizeof(Elf32_Ehdr));
}


void	parse_elf(int fd, char **err_msg)
{
	unsigned char	e_ident[EI_NIDENT];
	unsigned char	check_ver[5] = {0x7F, 'E', 'L', 'F', 1};

	ssize_t rd = read(fd, e_ident, EI_NIDENT);
	if (rd < EI_NIDENT)
		vprintf_exit(err_msg[ERR_READ], strerror(errno));

	if (ft_strncmp((char *)e_ident, (char *)check_ver, 4))
		vprintf_exit(err_msg[ERR_ELFHDR]);

	parse_e_indent(e_ident, err_msg);
	lseek(fd, 0, SEEK_SET);

	if (!ft_strncmp((char *)e_ident, (char *)check_ver, 5))
		parse_elf32(fd, err_msg);
	
	check_ver[4] = 2;
	if (!ft_strncmp((char *)e_ident, (char *)check_ver, 5))
		parse_elf64(fd, err_msg);
}