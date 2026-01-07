#include "woody.h"

void	payload_modify32(parsing_info *info, size_t payload_size, char **err_msg)
{
	((payload_info32 *) info->payload)->main_header_replace.e_shoff += payload_size;
	((payload_info32 *) info->payload)->main_header_replace.e_entry = ((payload_info32 *) info->payload)->insertion_header.p_vaddr + ((payload_info32 *) info->payload)->insertion_header.p_memsz;
	((payload_info32 *) info->payload)->insertion_header.p_filesz += payload_size;
	((payload_info32 *) info->payload)->insertion_header.p_memsz += payload_size;
}

void	payload_insert32(parsing_info *info, void *file_buf, size_t file_size, void *payload, size_t payload_size, char **err_msg)
{
	payload_modify32(info, payload_size, err_msg);
	size_t file_pos = ((payload_info32 *) info->payload)->main_header_replace.e_entry - ((payload_info32 *) info->payload)->insertion_header.p_vaddr + ((payload_info32 *) info->payload)->insertion_header.p_offset;
	void *new_file = malloc(file_size + payload_size);
	if (!new_file)
	{
		munmap(file_buf, file_size);
		munmap(payload, payload_size);
		freeall(2, info->encrypt, info->payload);
		vprintf_exit(ERR_MALLOC, err_msg);
	}
	ft_memcpy(file_buf, &((payload_info32 *) info->payload)->main_header_replace, sizeof(Elf32_Ehdr));
	ft_memcpy(file_buf + ((payload_info32 *) info->payload)->insert_hdr_pos, &((payload_info32 *) info->payload)->insertion_header, sizeof(Elf32_Phdr));
	ft_memcpy(new_file, file_buf, file_pos);
	ft_memcpy(new_file, payload, payload_size);
	ft_memcpy(new_file, file_buf + file_pos, file_size - file_pos);
	munmap(file_buf, file_size);
	munmap(payload, payload_size);
	freeall(2, info->encrypt, info->payload);
	create_woody(new_file, file_size, err_msg);
}