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

/// @brief data necessary to locate position of program section and encrypt
typedef struct t_encrypt_info {
	uint64_t	file_pos; //position of program section in file
	uint64_t	mem_addr; //position of program section in memory, litteral/offset if dynamic allocation or not
	uint64_t	file_size; //size of program section in file
	uint64_t 	old_entry_point;
} encrypt_info;

typedef struct t_parsing_info {
	uint8_t 		key[16];
	encrypt_info	*encrypt;
	void			*payload;
	bool			is_64;
} parsing_info;

typedef struct t_payload_info32 {
	Elf32_Ehdr	main_header_replace;
	Elf32_Phdr	insertion_header;
} payload_info32;

typedef struct t_payload_info64 {
	Elf64_Ehdr	main_header_replace;
	Elf64_Phdr	insertion_header;
} payload_info64;


/// @brief Error codes related to woody
typedef enum t_err {
	ERR_MMAP,
	ERR_STAT,
	ERR_NCODE,
	ERR_NELF,
	ERR_NEXEC,
	ERR_OSABI,
	ERR_ELFHDR,
	ERR_ENDIAN,
	ERR_OPEN,
	ERR_HELP,
	ERR_READ,
	ERR_MALLOC,
	ERR_MAX
} msg_err;

char	**init_msgs();
void	vprintf_exit(int err, char **err_msg, ...);
void	free_msg(char **err_msg);


void	freeall(unsigned int argsnbr, ...);

void	parse_elf(int fd, parsing_info *info, char **err_msg);
void	parse_elf32(int fd, parsing_info *info, char **err_msg);
void	parse_elf64(int fd, parsing_info *info, char **err_msg);
void	payload_insert(parsing_info *info, char *file_buf, char *exec_path, char **err_msg);
void	payload_insert32(parsing_info *info, char *file_buf, char *payload, size_t payload_size, char **err_msg);
void	payload_insert64(parsing_info *info, char *file_buf, char *payload, size_t payload_size, char **err_msg);
void 	xtea_encipher(unsigned int num_rounds, uint32_t tocipher[2], uint32_t const key[4]);
void 	*encrypt_engine(encrypt_info *info, char *filename, char **err_msg);
void 	*map_file(char *filename, size_t *size, char **err_msg);
void	generate_random_key(uint8_t *buffer, size_t size);


#endif