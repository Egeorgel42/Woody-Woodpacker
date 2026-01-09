#include "woody.h"

void	correct_section_header32(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload)
{
	Elf64_Off injection_offset = ((payload_info32 *) info->payload)->insertion_header.p_offset + ((payload_info32 *) info->payload)->insertion_header.p_filesz;
	Elf32_Shdr *sh_headers = executable->addr + ((payload_info32 *) info->payload)->main_header_replace.e_shoff;
	for (int i = 0; i < ((payload_info32 *) info->payload)->main_header_replace.e_shnum; i++)
	{
		if (sh_headers[i].sh_offset >= injection_offset)
		{
			sh_headers[i].sh_offset += payload->size;
		}
	}
}

void	payload_modify32(parsing_info *info, size_t payload_size)
{
	((payload_info32 *) info->payload)->main_header_replace.e_shoff += payload_size;
	((payload_info32 *) info->payload)->main_header_replace.e_entry = ((payload_info32 *) info->payload)->insertion_header.p_vaddr + ((payload_info32 *) info->payload)->insertion_header.p_memsz;
	((payload_info32 *) info->payload)->insertion_header.p_filesz += payload_size;
	((payload_info32 *) info->payload)->insertion_header.p_memsz += payload_size;
}

void	payload_insert32(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload, char **err_msg)
{
	payload_modify32(info, payload->size);
	size_t file_pos = ((payload_info32 *) info->payload)->main_header_replace.e_entry - ((payload_info32 *) info->payload)->insertion_header.p_vaddr + ((payload_info32 *) info->payload)->insertion_header.p_offset;
	void *new_file = malloc(executable->size + payload->size);
	if (!new_file)
	{
		munmap(executable->addr, executable->size);
		munmap(payload->addr, payload->size);
		free(info->payload);
		vprintf_exit(ERR_MALLOC, err_msg);
	}
	ft_memcpy(executable->addr, &((payload_info32 *) info->payload)->main_header_replace, sizeof(Elf32_Ehdr));
	ft_memcpy(executable->addr + ((payload_info32 *) info->payload)->insert_hdr_pos, &((payload_info32 *) info->payload)->insertion_header, sizeof(Elf32_Phdr));
	ft_memcpy(new_file, executable->addr, file_pos);
	ft_memcpy(new_file + file_pos, payload->addr, payload->size);
	ft_memcpy(new_file + file_pos + payload->size, executable->addr + file_pos, executable->size - file_pos);
	munmap(executable->addr, executable->size);
	munmap(payload->addr, payload->size);
	free(info->payload);
	create_woody(new_file, executable->size + payload->size, err_msg);
}