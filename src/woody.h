#ifndef WOODY_H
# define WOODY_H
# include "../Libft/libft.h"
# include <elf.h>
# include <stdio.h>
# include <unistd.h>
# include <errno.h>
# include <string.h>
# include <fcntl.h>
# include <sys/mman.h> 
# include <sys/stat.h> 
# include <sys/types.h>
# include <limits.h>

# include "terminal_output.h"

# define PAYLOAD32 PAYLOAD_DIR "/payload32.bin"
# define PAYLOAD64 PAYLOAD_DIR "/payload64.bin"

typedef struct t_mmap_alloc {
	void	*addr;
	size_t	size;
} mmap_alloc;

typedef struct t_parsing_info {
	uint64_t		file_pos; //position of program section in file
	uint64_t		mem_addr; //position of program section in memory, litteral/offset if dynamic allocation or not
	uint64_t		file_size; //size of program section in file
	uint8_t 		key[16];
	bool			is_64;
	size_t			text_shdr_index;
} parsing_info;

parsing_info	parse_elf(int fd);
parsing_info	parse_elf32(int fd);
parsing_info	parse_elf64(int fd);

off_t	get_file_size(int fd);
void	seek_exact(int fd, uint64_t offset);
void	read_exact(int fd, void *buffer, size_t size);
void	*read_alloc(int fd, uint64_t offset, size_t size);
bool	valid_range(uint64_t file_size, uint64_t offset, uint64_t size);
bool	valid_table(uint64_t file_size, uint64_t offset, uint64_t count,
		uint64_t entry_size, size_t *table_size);

void	correct_section_header32(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload);
void	correct_section_header64(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload);

void	payload_insert(parsing_info *info, mmap_alloc *executable);
void	payload_insert32(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload);
void	payload_insert64(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload);

void 		xtea_encipher(unsigned int num_rounds, uint32_t tocipher[2], uint32_t const key[4]);
mmap_alloc	encrypt_engine(parsing_info *info, char *filename);
void 		create_woody(void *file_ptr, size_t total_file_size);

#endif