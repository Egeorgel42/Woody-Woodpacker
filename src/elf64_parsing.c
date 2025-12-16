#include "../include/woody.h"

/// @brief check for type of program header, if no PT_INTERP are present, then that means this is not an executable but a dynamic library (.so)
static void	check_PIE64(int fd, char **err_msg, Elf64_Ehdr *header)
{
	bool	is_executable = false;
	size_t	size = header->e_phentsize * header->e_phnum;

	Elf64_Phdr	*pgr_hdr = malloc(size);
	if (!pgr_hdr)
	{
		close(fd);
		vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}

	lseek(fd, header->e_phoff, SEEK_SET); //set read location to e_phoff
	size_t rd = read(fd, pgr_hdr, size);
	if (rd < size)
	{
		close(fd);
		free(pgr_hdr);
		vprintf_exit(ERR_READ, err_msg, strerror(errno));
	}

	for (int i = 0; i < header->e_phnum; i++)
	{
		if (pgr_hdr[i].p_type == PT_INTERP)
			is_executable = true;
	}
	if (!is_executable)
	{
		close(fd);
		free(pgr_hdr);
		vprintf_exit(ERR_NEXEC, err_msg);
	}
}

/// @brief allocate and return .text section data that need to be encrypted
static void get_pgr_info(int fd, char **err_msg, encrypt_info **info, Elf64_Ehdr *header, Elf64_Shdr *sh_hdr)
{
	unsigned int j = 0;
	for (int i = 0; i < header->e_phnum; i++)
	{
		if (sh_hdr[i].sh_type == SHT_PROGBITS && (sh_hdr[i].sh_flags & SHF_EXECINSTR))
			j++;
	}
	if (!j)
	{
		close(fd);
		free(sh_hdr);
		vprintf_exit(ERR_NCODE, err_msg);
	}

	*info = malloc(sizeof(encrypt_info) * (j + 1));
	if (!*info)
	{
		close(fd);
		free(sh_hdr);
		vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}
	j = 0;

	for (int i = 0; i < header->e_phnum; i++)
	{
		if (sh_hdr[i].sh_type == SHT_PROGBITS && (sh_hdr[i].sh_flags & SHF_EXECINSTR))
		{
			(*info)[j].file_pos = sh_hdr[i].sh_offset;
			(*info)[j].file_size = sh_hdr[i].sh_size;
			(*info)[j].mem_addr = sh_hdr[i].sh_addr;
			j++;
		}
	}
	ft_bzero(&(*info)[j], sizeof(encrypt_info));
	free(sh_hdr);
}

static payload_info64	*get_payload_info(int fd, char **err_msg, Elf64_Ehdr *header, void *freedata)
{
	payload_info64 *headers = malloc(sizeof(payload_info64));
	if (!headers)
	{
		close(fd);
		free(freedata);
		vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}
	//continue by getting Phdr and ehdr to payload info.
}

/// @brief read all of the program headers using "e_phoff (location of headers)" "e_phnum (num of header)" "e_phentsize (size of headers)" and parse them, if executable is dynamic check_PIE
static payload_info64 *parse_pgr64(int fd, encrypt_info **info, char **err_msg, Elf64_Ehdr *header)
{
	size_t	size = header->e_shentsize * header->e_shnum;

	Elf64_Shdr	*pgr_hdr = malloc(size);
	if (!pgr_hdr)
	{
		close(fd);
		vprintf_exit(ERR_READ, err_msg, strerror(errno));
	}

	lseek(fd, header->e_shoff, SEEK_SET); //set read location to e_phoff
	size_t rd = read(fd, pgr_hdr, size);
	if (rd < size)
	{
		close(fd);
		free(pgr_hdr);
		vprintf_exit(ERR_READ, err_msg, strerror(errno));
	}

	get_pgr_info(fd, err_msg, info, header, pgr_hdr);
	return get_payload_info(fd, err_msg, header, info);
}

payload_info64	*parse_elf64(int fd, encrypt_info **info, char **err_msg)
{
	Elf64_Ehdr	header;
	size_t rd = read(fd, &header, sizeof(Elf64_Ehdr));
	if (rd < sizeof(Elf64_Ehdr))
	{
		close(fd);
		vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
	}
	if (header.e_type != ET_EXEC && header.e_type != ET_DYN) // check for executable or dynamic program
	{
		close(fd);
		vprintf_exit(ERR_NEXEC, err_msg);
	}
	if (header.e_version == EV_NONE || header.e_version != EV_CURRENT)
	{
		close(fd);
		vprintf_exit(ERR_ELFHDR, err_msg);
	}
	if (header.e_type == ET_DYN)
		check_PIE64(fd, err_msg, &header);
	return parse_pgr64(fd, info, err_msg, &header);
}