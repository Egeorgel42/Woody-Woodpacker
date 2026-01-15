#include "woody.h"

/// @brief read all of the program headers using "e_phoff (location of headers)" "e_phnum (num of header)" "e_phentsize (size of headers)" and parse them, if executable is dynamic check_PIE
static Elf32_Shdr *get_s_hdr(int fd, char **err_msg, Elf32_Ehdr *header)
{
	size_t	size = header->e_shentsize * header->e_shnum;

	Elf32_Shdr	*s_hdr = malloc(size);
	if (!s_hdr)
	{
		close(fd);
		vprintf_exit(ERR_READ, err_msg, strerror(errno));
	}

	lseek(fd, header->e_shoff, SEEK_SET); //set read location to e_phoff
	size_t rd = read(fd, s_hdr, size);
	if (rd < size)
	{
		close(fd);
		free(s_hdr);
		vprintf_exit(ERR_READ, err_msg, strerror(errno));
	}
	return s_hdr;
}

/// @brief allocate and return .text section data that need to be encrypted
static void get_encrypt_info(int fd, parsing_info *info, Elf32_Ehdr *header, char **err_msg)
{
	Elf32_Shdr *res = NULL;
	Elf32_Shdr *s_hdr = get_s_hdr(fd, err_msg, header);
	char *buffer = malloc(s_hdr[header->e_shstrndx].sh_size);
	if (!buffer)
	{
		close(fd);
		free(s_hdr);
		vprintf_exit(ERR_MALLOC, err_msg);
	}

	lseek(fd, s_hdr[header->e_shstrndx].sh_offset, SEEK_SET);
	read(fd, buffer, s_hdr[header->e_shstrndx].sh_size);

	for (int i = 0; i < header->e_shnum; i++)
	{
		if (!ft_strcmp(buffer + s_hdr[i].sh_name, ".text"))
		{
			res = s_hdr;
			info->text_shdr_index = i;
			break;
		}
	}

	free(buffer);
	if (!res)
	{
		close(fd);
		free(s_hdr);
		vprintf_exit(ERR_NCODE, err_msg);
	}

	info->encrypt.file_pos = res->sh_offset;
	info->encrypt.file_size = res->sh_size;
	info->encrypt.mem_addr = res->sh_addr;
	free(s_hdr);
}

static Elf32_Phdr *get_p_hdr(int fd, char **err_msg, Elf32_Ehdr *header)
{
	size_t	size = header->e_phentsize * header->e_phnum;

	Elf32_Phdr	*p_hdr = malloc(size);
	if (!p_hdr)
	{
		close(fd);
		vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}

	lseek(fd, header->e_phoff, SEEK_SET); //set read location to e_phoff
	size_t rd = read(fd, p_hdr, size);
	if (rd < size)
	{
		close(fd);
		free(p_hdr);
		vprintf_exit(ERR_READ, err_msg, strerror(errno));
	}
	return p_hdr;
}

/// @brief gets specific phdr header to insert payload in, also checks for PIE to verify if file is an actual executable
static void get_payload_info(int fd, Elf32_Ehdr *header, char **err_msg)
{
	Elf32_Phdr *p_hdr = get_p_hdr(fd, err_msg, header);
	bool		is_executable = false;

	for (int i = 0; i < header->e_phnum; i++)
	{
		if (p_hdr[i].p_type == PT_INTERP)
		{
			is_executable = true;
			break;
		}
	}

	free(p_hdr);
	if (!(is_executable))
	{
		close(fd);
		if (!is_executable)
			vprintf_exit(ERR_NEXEC, err_msg);
		vprintf_exit(ERR_ELFHDR, err_msg);
	}
}

parsing_info	parse_elf32(int fd, char **err_msg)
{
	parsing_info info;
	Elf32_Ehdr	header;
	size_t rd = read(fd, &header, sizeof(Elf32_Ehdr));
	if (rd < sizeof(Elf32_Ehdr))
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
	info.is_64 = false;
	info.text_shdr_index = 0;

	get_encrypt_info(fd, &info, &header, err_msg);
	get_payload_info(fd, &header, err_msg);
	return info;
}