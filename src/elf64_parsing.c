#include "woody.h"
/*
static void	check_PIE64(int fd, char **err_msg, Elf64_Ehdr *header)
{
	for (int i = 0; i < header->e_phnum; i++)
	{
		Elf64_Phdr	pgr;
		size_t rd = read(fd, &pgr, sizeof(Elf64_Ehdr));

	}

}*/

void	parse_elf64(int fd, char **err_msg)
{
	Elf64_Ehdr	header;
	size_t rd = read(fd, &header, sizeof(Elf64_Ehdr));
	if (rd < sizeof(Elf64_Ehdr))
		vprintf_exit(err_msg[ERR_OPEN], strerror(errno));
	if (header.e_type != ET_EXEC && header.e_type != ET_DYN)
		vprintf_exit(err_msg[ERR_NEXEC]);
	if (header.e_version == EV_NONE || header.e_version != EV_CURRENT)
		vprintf_exit(err_msg[ERR_ELFHDR]);
	//if (header.e_type == ET_DYN)
		//check_PIE64(fd, err_msg, &header);
}