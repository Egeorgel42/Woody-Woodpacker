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

# define PAYLOAD32 "Payload/payload32.bin"
# define PAYLOAD64 "Payload/payload64.bin"

typedef struct t_mmap_alloc {
	void	*addr;
	size_t	size;
} mmap_alloc;

/// @brief data necessary to locate position of program section and encrypt
typedef struct t_encrypt_info {
	uint64_t	file_pos; //position of program section in file
	uint64_t	mem_addr; //position of program section in memory, litteral/offset if dynamic allocation or not
	uint64_t	file_size; //size of program section in file
	uint8_t 	key[16];
} encrypt_info;

typedef struct t_parsing_info {
	encrypt_info	encrypt;
	bool			is_64;
	size_t			text_shdr_index;
} parsing_info;

/// @brief Error codes related to woody
typedef enum t_err {
	ERR_MMAP,
	ERR_STAT,
	ERR_NCODE,
	ERR_NELF,
	ERR_NEXEC,
	ERR_OSABI,
	ERR_CAVE,
	ERR_ELFHDR,
	ERR_ENDIAN,
	ERR_OPEN,
	ERR_HELP,
	ERR_READ,
	ERR_WRITE,
	ERR_MALLOC,
	ERR_MAX
} msg_err;

char	**init_msgs();
void	vprintf_exit(int err, char **err_msg, ...);
void	free_msg(char **err_msg);

parsing_info	parse_elf(int fd, char **err_msg);
parsing_info	parse_elf32(int fd, char **err_msg);
parsing_info	parse_elf64(int fd, char **err_msg);


void	correct_section_header32(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload);
void	correct_section_header64(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload);

void	payload_insert(parsing_info *info, mmap_alloc *executable, char *exec_path, char **err_msg);
void	payload_insert32(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload, char **err_msg);
void	payload_insert64(parsing_info *info, mmap_alloc *executable, mmap_alloc *payload, char **err_msg);

void 		xtea_encipher(unsigned int num_rounds, uint32_t tocipher[2], uint32_t const key[4]);
mmap_alloc	encrypt_engine(parsing_info *info, char *filename, char **err_msg);
void 		create_woody(void *file_ptr, size_t total_file_size, char **err_msg);

#endif