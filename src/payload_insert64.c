#include "woody.h"

void	correct_section_header64(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload)
{
	Elf64_Ehdr *main_header = &((payload_info64 *) info->payload)->main_header_replace;
	size_t injection_offset = ((payload_info64 *) info->payload)->insertion_header.p_offset + ((payload_info64 *) info->payload)->insertion_header.p_filesz;
	Elf64_Shdr *sh_headers = executable->addr + main_header->e_shoff;
	for (int i = 0; i < main_header->e_shnum; i++)
	{
		if (sh_headers[i].sh_offset >= injection_offset)
		{
			sh_headers[i].sh_offset += payload->size;
		}
	}
	char *strtab = (char *)executable->addr + sh_headers[main_header->e_shstrndx].sh_offset;
	size_t encrypted_offset = 0;
	for (int i = 0; i < main_header->e_shnum; i++)
	{
        if (strcmp(strtab + sh_headers[i].sh_name, ".text") == 0) {
            encrypted_offset = sh_headers[i].sh_offset;
			break;
        }
    }
	Elf64_Phdr *ph_headers = executable->addr + main_header->e_phoff;
	for (int i = 0; i < main_header->e_phnum; i++)
	{
        if (ph_headers[i].p_type == PT_LOAD && encrypted_offset >= ph_headers[i].p_offset && 
            encrypted_offset < (ph_headers[i].p_offset + ph_headers[i].p_filesz))
		{
			ph_headers[i].p_flags = PF_W | PF_R;
			break;
		}
    }
}

void	payload_modify64(parsing_info *info, size_t payload_size)
{
	((payload_info64 *) info->payload)->main_header_replace.e_shoff += payload_size;
	((payload_info64 *) info->payload)->main_header_replace.e_entry = ((payload_info64 *) info->payload)->insertion_header.p_vaddr + ((payload_info64 *) info->payload)->insertion_header.p_memsz;
	((payload_info64 *) info->payload)->insertion_header.p_filesz += payload_size;
	((payload_info64 *) info->payload)->insertion_header.p_memsz += payload_size;
}

void	payload_insert64(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload, char **err_msg)
{
	payload_modify64(info, payload->size);
	size_t file_pos = ((payload_info64 *) info->payload)->main_header_replace.e_entry - ((payload_info64 *) info->payload)->insertion_header.p_vaddr + ((payload_info64 *) info->payload)->insertion_header.p_offset;
	void *new_file = malloc(executable->size + payload->size);
	if (!new_file)
	{
		munmap(executable->addr, executable->size);
		munmap(payload->addr, payload->size);
		free(info->payload);
		vprintf_exit(ERR_MALLOC, err_msg);
	}
	ft_memcpy(executable->addr, &((payload_info64 *) info->payload)->main_header_replace, sizeof(Elf64_Ehdr));
	ft_memcpy(executable->addr + ((payload_info64 *) info->payload)->insert_hdr_pos, &((payload_info64 *) info->payload)->insertion_header, sizeof(Elf64_Phdr));
	ft_memcpy(new_file, executable->addr, file_pos);
	ft_memcpy(new_file + file_pos, payload->addr, payload->size);
	ft_memcpy(new_file + file_pos + payload->size, executable->addr + file_pos, executable->size - file_pos);
	munmap(executable->addr, executable->size);
	munmap(payload->addr, payload->size);
	free(info->payload);
	create_woody(new_file, executable->size + payload->size, err_msg);
}