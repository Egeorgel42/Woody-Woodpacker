#ifndef WOODY_H
# define WOODY_H
# include "../libft/libft.h"
# include <elf.h>
# include <stdio.h>
# include <unistd.h>
# include <errno.h>
# include <string.h>
# include <fcntl.h>

/// @brief data necessary to locate position of program section and encrypt
typedef struct t_encrypt_info {
	uint64_t	file_pos; //position of program section in file
	uint64_t	mem_addr; //position of program section in memory, litteral/offset if dynamic allocation or not
	uint64_t	file_size; //size of program section in file
	uint64_t	mem_size; //size of program section in memory, equal file_size + size of .bss for the section
} encrypt_info;

/// @brief Error codes related to woody
typedef enum t_err {
	ERR_NCODE,
	ERR_NELF,
	ERR_NEXEC,
	ERR_OSABI,
	ERR_ELFHDR,
	ERR_ENDIAN,
	ERR_OPEN,
	ERR_HELP,
	ERR_READ,
	ERR_MAX
} msg_err;

char		**init_msgs();
void		vprintf_exit(int err, char **err_msg, ...);
void		free_msg(char **err_msg);

encrypt_info	*parse_elf(int fd, char **err_msg);
encrypt_info *parse_elf32(int fd, char **err_msg);
encrypt_info *parse_elf64(int fd, char **err_msg);
void 		xtea_encipher(unsigned int num_rounds, uint32_t tocipher[2], uint32_t const key[4]);
void 		encrypt_engine(encrypt_info *info, char **argv);
void 		*map_file(char *filename, size_t *size, char **err_msg);
void		generate_random_key(uint8_t *buffer, size_t size);



#endif