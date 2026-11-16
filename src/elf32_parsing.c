#include "woody.h"

/// @brief read all of the program headers using "e_phoff (location of headers)" "e_phnum (num of header)" "e_phentsize (size of headers)" and parse them, if executable is dynamic check_PIE
static Elf32_Shdr *get_s_hdr(int fd, Elf32_Ehdr *header)
{
	size_t	size = header->e_shentsize * header->e_shnum;

	Elf32_Shdr	*s_hdr = malloc(size);
	if (!s_hdr)
	{
		close(fd);
		error(ERR_MALLOC, strerror(errno));
	}

	seek_safe(fd, header->e_shoff);
	if (!read_safe(fd, s_hdr, size)) {
		close(fd);
		free(s_hdr);
		error(ERR_READ, strerror(errno));
	}
	return s_hdr;
}

/// @brief allocate and return .text section data that need to be encrypted
static void get_encrypt_info(int fd, parsing_info *info, Elf32_Ehdr *header)
{
	Elf32_Shdr *res = NULL;
	Elf32_Shdr *s_hdr = get_s_hdr(fd, header);
	char *buffer = malloc(s_hdr[header->e_shstrndx].sh_size);
	if (!buffer)
	{
		close(fd);
		free(s_hdr);
		error(ERR_MALLOC, strerror(errno));
	}

	seek_safe(fd, s_hdr[header->e_shstrndx].sh_offset);
	if (!read_safe(fd, buffer, s_hdr[header->e_shstrndx].sh_size)) {
		close(fd);
		free(buffer);
		free(s_hdr);
		error(ERR_READ, strerror(errno));
	}

	for (int i = 0; i < header->e_shnum; i++)
	{
		if (ft_strcmp(buffer + s_hdr[i].sh_name, ".text") == 0)
		{
			res = &s_hdr[i];
			info->text_shdr_index = i;
			break;
		}
	}

	free(buffer);
	if (!res)
	{
		close(fd);
		free(s_hdr);
		error(ERR_NCODE);
	}

	info->file_pos = res->sh_offset;
	info->file_size = res->sh_size;
	info->mem_addr = res->sh_addr;
	free(s_hdr);
}

static Elf32_Phdr *get_p_hdr(int fd, Elf32_Ehdr *header)
{
	size_t	size = header->e_phentsize * header->e_phnum;

	Elf32_Phdr	*p_hdr = malloc(size);
	if (!p_hdr)
	{
		close(fd);
		error(ERR_MALLOC, strerror(errno));
	}

	seek_safe(fd, header->e_phoff);
	if (!read_safe(fd, p_hdr, size)) {
		close(fd);
		free(p_hdr);
		error(ERR_READ, strerror(errno));
	}
	return p_hdr;
}

/// @brief gets specific phdr header to insert payload in, also checks for PIE to verify if file is an actual executable
static void get_payload_info(int fd, Elf32_Ehdr *header)
{
	Elf32_Phdr *p_hdr = get_p_hdr(fd, header);
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
		if (!is_executable) {
			error(ERR_NEXEC);
		}
		error(ERR_ELFHDR);
	}
}

parsing_info	parse_elf32(int fd)
{
	parsing_info info;
	Elf32_Ehdr	header;
	if (!read_safe(fd, &header, sizeof(Elf32_Ehdr))) {
		close(fd);
		error(ERR_OPEN, strerror(errno));
	}
	if (header.e_type != ET_EXEC && header.e_type != ET_DYN) // check for executable or dynamic program
	{
		close(fd);
		error(ERR_NEXEC);
	}
	if (header.e_version == EV_NONE || header.e_version != EV_CURRENT)
	{
		close(fd);
		error(ERR_ELFHDR);
	}
	info.is_64 = false;
	info.text_shdr_index = 0;

	get_encrypt_info(fd, &info, &header);
	get_payload_info(fd, &header);
	return info;
}