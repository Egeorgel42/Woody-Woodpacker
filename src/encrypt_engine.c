#include "woody.h"
#include <sys/mman.h> 
#include <sys/stat.h> 
#include <sys/types.h>

#define KEY_SIZE 16
// 128 bits key = 16 bytes

static void generate_random_key(uint8_t *buffer, size_t size)
{
	// using dev/urandom for randomly generating the key
	int fd = open("/dev/urandom", O_RDONLY);
    error_if(fd == -1, ERR_OPEN, strerror(errno));

    bool success = read_safe(fd, buffer, size);
    close(fd);
    error_if(!success, ERR_READ, strerror(errno));
}

static mmap_alloc	map_file(int fd)
{
	mmap_alloc executable;

    executable.size = get_file_size(fd);
    executable.addr = mmap(NULL, executable.size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    error_if(executable.addr == MAP_FAILED, ERR_MMAP, strerror(errno));
    return executable;
}

mmap_alloc	encrypt_engine(parsing_info *info, int fd)
{
    mmap_alloc executable = map_file(fd);

    generate_random_key(info->key, KEY_SIZE);

    printf("key_value: ");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02X", info->key[i]);
    }
    printf("\n");
    
    uint32_t *xtea_key = (uint32_t *)info->key;

    // Calculate pointer to the data to encrypt, using
    // the file start + file offset
    uint8_t *section_ptr = (uint8_t *)executable.addr + info->file_pos;

    // Ciphering
    // Convert section pointer to uint32_t* for XTEA
    uint32_t *code_ptr = (uint32_t *)section_ptr;
    
    // info->file_size = number of bytes to cipher, divided by 8 since XTEA needs 64bits blocks
    size_t num_blocks = info->file_size / 8;

    for (size_t i = 0; i < num_blocks; i++) {
        xtea_encipher(32, &code_ptr[i * 2], xtea_key);
    }
    return executable;
}
