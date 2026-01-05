#include "../include/woody.h"

/// @brief read all of the program headers using "e_phoff (location of headers)" "e_phnum (num of header)" "e_phentsize (size of headers)" and parse them, if executable is dynamic check_PIE
static Elf64_Shdr *get_s_hdr(int fd, char **err_msg, parsing_info *info, Elf64_Ehdr *header)
{
	size_t	size = header->e_shentsize * header->e_shnum;

	Elf64_Shdr	*s_hdr = malloc(size);
	if (!s_hdr)
	{
		close(fd);
		if (info->encrypt)
			free(info->encrypt);
		if (info->payload)
			free(info->payload);
		vprintf_exit(ERR_READ, err_msg, strerror(errno));
	}

	lseek(fd, header->e_shoff, SEEK_SET); //set read location to e_phoff
	size_t rd = read(fd, s_hdr, size);
	if (rd < size)
	{
		close(fd);
		if (info->encrypt)
			free(info->encrypt);
		if (info->payload)
			free(info->payload);
		free(s_hdr);
		vprintf_exit(ERR_READ, err_msg, strerror(errno));
	}
	return s_hdr;
}

/// @brief allocate and return .text section data that need to be encrypted
static void get_encrypt_info(int fd, char **err_msg, parsing_info *info, Elf64_Ehdr *header)
{
	Elf64_Shdr *s_hdr = get_s_hdr(fd, err_msg, info, header);
	unsigned int j = 0;
	for (int i = 0; i < header->e_shnum; i++)
	{
		if (s_hdr[i].sh_type == SHT_PROGBITS && (s_hdr[i].sh_flags & SHF_EXECINSTR))
			j++;
	}
	if (!j)
	{
		close(fd);
		free(s_hdr);
		if (info->payload)
			free(info->payload);
		vprintf_exit(ERR_NCODE, err_msg);
	}

	info->encrypt = malloc(sizeof(encrypt_info) * (j + 1));
	if (!info->encrypt)
	{
		close(fd);
		free(s_hdr);
		if (info->payload)
			free(info->payload);
		vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}
	j = 0;

	for (int i = 0; i < header->e_shnum; i++)
	{
		if (s_hdr[i].sh_type == SHT_PROGBITS && (s_hdr[i].sh_flags & SHF_EXECINSTR))
		{
			info->encrypt[j].file_pos = s_hdr[i].sh_offset;
			info->encrypt[j].file_size = s_hdr[i].sh_size;
			info->encrypt[j].mem_addr = s_hdr[i].sh_addr;
			j++;
		}
	}
	ft_bzero(&info->encrypt[j], sizeof(encrypt_info));
	free(s_hdr);
}

static Elf64_Phdr *get_p_hdr(int fd, char **err_msg, parsing_info *info, Elf64_Ehdr *header)
{
	size_t	size = header->e_phentsize * header->e_phnum;

	Elf64_Phdr	*p_hdr = malloc(size);
	if (!p_hdr)
	{
		close(fd);
		if (info->encrypt)
			free(info->encrypt);
		if (info->payload)
			free(info->payload);
		vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}

	lseek(fd, header->e_phoff, SEEK_SET); //set read location to e_phoff
	size_t rd = read(fd, p_hdr, size);
	if (rd < size)
	{
		close(fd);
		if (info->encrypt)
			free(info->encrypt);
		if (info->payload)
			free(info->payload);
		free(p_hdr);
		vprintf_exit(ERR_READ, err_msg, strerror(errno));
	}
	return p_hdr;
}

/// @brief gets specific phdr header to insert payload in, also checks for PIE to verify if file is an actual executable
static void get_payload_info(int fd, char **err_msg, parsing_info *info, Elf64_Ehdr *header)
{
	Elf64_Phdr *p_hdr = get_p_hdr(fd, err_msg, info, header);
	info->payload = malloc(sizeof(payload_info64));
	if (!info->payload)
	{
		close(fd);
		free(p_hdr);
		if (info->encrypt)
			free(info->encrypt);
		vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}

	((payload_info64 *) info->payload)->main_header_replace = *header;
	bool	is_executable = false;
	bool	copied_header = false;

	for (int i = 0; i < header->e_phnum; i++)
	{
		if (p_hdr[i].p_type == PT_INTERP)
			is_executable = true;
		if (p_hdr[i].p_type == PT_LOAD && (p_hdr[i].p_flags & PF_W))
		{
			((payload_info64 *) info->payload)->insertion_header = p_hdr[i];
			copied_header = true;
		}
	}

	free(p_hdr);
	if (!(is_executable && copied_header))
	{
		close(fd);
		free(info->payload);
		if (info->encrypt)
			free(info->encrypt);
		if (!is_executable)
			vprintf_exit(ERR_NEXEC, err_msg);
		vprintf_exit(ERR_ELFHDR, err_msg);
	}
}

void	parse_elf64(int fd, parsing_info *info, char **err_msg)
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

	get_encrypt_info(fd, err_msg, info, &header);
	get_payload_info(fd, err_msg, info, &header);
}