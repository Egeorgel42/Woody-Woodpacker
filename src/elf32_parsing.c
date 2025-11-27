#include "../include/woody.h"

/// @brief check for type of program header, if no PT_INTERP are present, then that means this is not an executable but a dynamic library (.so)
static void	check_PIE32(char **err_msg, Elf32_Ehdr *header, Elf32_Phdr *pgr_hdr)
{
	bool	is_executable = false;

	for (int i = 0; i < header->e_phnum; i++)
	{
		if (pgr_hdr[i].p_type == PT_INTERP)
			is_executable = true;
	}
	if (!is_executable)
	{
		free(pgr_hdr);
		vprintf_exit(ERR_NEXEC, err_msg);
	}
}

/// @brief allocate and return .text section data that need to be encrypted
static encrypt_info *get_pgr_info(char **err_msg, Elf32_Ehdr *header, Elf32_Phdr	*pgr_hdr)
{
	unsigned int j = 0;
	for (int i = 0; i < header->e_phnum; i++)
	{
		if (pgr_hdr[i].p_type == PT_LOAD && (pgr_hdr[i].p_flags & PF_X))
			j++;
	}
	if (!j)
	{
		free(pgr_hdr);
		vprintf_exit(ERR_NCODE, err_msg);
	}

	encrypt_info	*info = malloc(sizeof(encrypt_info) * j + 1);
	j = 0;

	for (int i = 0; i < header->e_phnum; i++)
	{
		if (pgr_hdr[i].p_type == PT_LOAD && pgr_hdr[i].p_flags == PF_X)
		{
			info[j].file_pos = pgr_hdr[i].p_offset;
			info[j].file_size = pgr_hdr[i].p_filesz;
			info[j].mem_size = pgr_hdr[i].p_memsz;
			info[j].mem_addr = pgr_hdr[i].p_vaddr;
			j++;
		}
	}
	free(pgr_hdr);
	return info;
}

/// @brief read all of the program headers using "e_phoff (location of headers)" "e_phnum (num of header)" "e_phentsize (size of headers)" and parse them, if executable is dynamic check_PIE
static encrypt_info *parse_pgr32(int fd, char **err_msg, Elf32_Ehdr *header)
{
	size_t	size = header->e_phentsize * header->e_phnum;

	Elf32_Phdr	*pgr_hdr = malloc(size);
	lseek(fd, header->e_phoff, SEEK_SET); //set read location to e_phoff
	size_t rd = read(fd, pgr_hdr, size);
	if (rd < size)
	{
		free(pgr_hdr);
		vprintf_exit(ERR_READ, err_msg, strerror(errno));
	}
	if (header->e_type == ET_DYN)
		check_PIE32(err_msg, header, pgr_hdr);
	return get_pgr_info(err_msg, header, pgr_hdr);
}

encrypt_info	*parse_elf32(int fd, char **err_msg)
{
	Elf32_Ehdr	header;
	size_t rd = read(fd, &header, sizeof(Elf32_Ehdr));
	if (rd < sizeof(Elf32_Ehdr))
		vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
	if (header.e_type != ET_EXEC && header.e_type != ET_DYN) // check for executable or dynamic program
		vprintf_exit(ERR_NEXEC, err_msg);
	if (header.e_version == EV_NONE || header.e_version != EV_CURRENT)
		vprintf_exit(ERR_ELFHDR, err_msg);
	return parse_pgr32(fd, err_msg, &header);
}