#include "woody.h"

static void	check_PIE32(int fd, char **err_msg, Elf32_Ehdr *header)
{
	bool	is_executable = false;

	Elf32_Phdr	*pgr = malloc(header->e_phentsize * header->e_phnum);
	lseek(fd, header->e_phoff, SEEK_SET);
	for (int i = 0; i < header->e_phnum; i++)
	{
		size_t rd = read(fd, &pgr[i], header->e_phentsize);
		if (rd < header->e_phentsize)
			vprintf_exit(err_msg[ERR_READ], strerror(errno));
	}
	for (int i = 0; i < header->e_phnum; i++)
	{
		if (pgr[i].p_type == PT_INTERP)
			is_executable = true;
	}
	if (!is_executable)
		vprintf_exit(err_msg[ERR_NEXEC]);
	free(pgr);
}
void	parse_elf32(int fd, char **err_msg)
{
	Elf32_Ehdr	header;
	size_t rd = read(fd, &header, sizeof(Elf32_Ehdr));
	if (rd < sizeof(Elf32_Ehdr))
		vprintf_exit(err_msg[ERR_OPEN], strerror(errno));
	if (header.e_type != ET_EXEC && header.e_type != ET_DYN)
		vprintf_exit(err_msg[ERR_NEXEC]);
	if (header.e_version == EV_NONE || header.e_version != EV_CURRENT)
		vprintf_exit(err_msg[ERR_ELFHDR]);
	if (header.e_type == ET_DYN)
		check_PIE32(fd, err_msg, &header);
}
