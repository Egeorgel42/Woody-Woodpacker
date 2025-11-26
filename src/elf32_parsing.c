#include "woody.h"

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
}
