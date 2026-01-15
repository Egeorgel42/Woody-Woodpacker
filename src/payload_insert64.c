#include "woody.h"

/// @brief will modify executable elf headers phdr and shdr
/// @return position of were executable should be inserted
static size_t	payload_modify64(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload, char **err_msg)
{
	Elf64_Ehdr *main_header = executable->addr;
	Elf64_Shdr *sh_headers = executable->addr + main_header->e_shoff;
	Elf64_Phdr *p_headers = executable->addr + main_header->e_phoff;
	Elf64_Phdr *insert_hdr = NULL;
	size_t		text_phdr_index = -1;
	//find p_header corresponding to .text (encrypted) section and modify permitions
	for (int i = 0; i < main_header->e_phnum; i++)
	{
        if (p_headers[i].p_type == PT_LOAD && sh_headers[info->text_shdr_index].sh_offset >= p_headers[i].p_offset && 
            sh_headers[info->text_shdr_index].sh_offset < (p_headers[i].p_offset + p_headers[i].p_filesz))
		{
			p_headers[i].p_flags = PF_W | PF_R;
			text_phdr_index = i;
		}
	}
	if (text_phdr_index == (size_t)-1)
	{
		munmap(executable->addr, executable->size);
		munmap(payload->addr, payload->size);
		vprintf_exit(ERR_ELFHDR, err_msg);
	}
	//find a program section that has a code cave big enough to insert payload, if it is the last program section, move all section header by the payload size
	for (size_t i = 0; i < main_header->e_phnum; i++)
	{
		if (text_phdr_index == i)
			continue;
		size_t code_cave_end = executable->size - (main_header->e_shnum * main_header->e_shentsize);
		if (i + 1 < main_header->e_phnum)
		{
			code_cave_end = p_headers[i + 1].p_offset;
			if (p_headers[i].p_filesz + p_headers[i].p_offset + payload->size < code_cave_end)
			{
				insert_hdr = &p_headers[i];
				break;
			}
		}
		else if (p_headers[i].p_filesz + p_headers[i].p_offset + payload->size < code_cave_end)
		{
			ft_memmove(sh_headers, sh_headers + payload->size, main_header->e_shentsize * main_header->e_shnum);
			insert_hdr = &p_headers[i];
			main_header->e_shoff += payload->size;
			for (size_t j = 0; j < main_header->e_shnum; j++)
			{
				sh_headers[j].sh_offset += payload->size;
			}
			break;
		}
	}
	size_t injection_offset = insert_hdr->p_offset + insert_hdr->p_filesz;
	
	main_header->e_entry = insert_hdr->p_vaddr + insert_hdr->p_memsz;
	insert_hdr->p_filesz += payload->size;
	insert_hdr->p_memsz += payload->size;
	insert_hdr->p_flags = PF_X | PF_R;
	return injection_offset;
}

void	payload_insert64(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload, char **err_msg)
{
	size_t payload_pos =  payload_modify64(info, executable, payload, err_msg);
	ft_memcpy(executable->addr + payload_pos, payload->addr, payload->size);
	munmap(payload->addr, payload->size);
	create_woody(executable->addr, executable->size, err_msg);
	munmap(executable->addr, executable->size);
}