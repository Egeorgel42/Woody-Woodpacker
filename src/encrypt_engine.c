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
	if (fd == -1) {
		perror("Fatal: Failed to open /dev/urandom");
		exit(EXIT_FAILURE);
	}

	// read 'size' bytes into buffer
	ssize_t bytes_read = read(fd, buffer, size);
	if (bytes_read != (ssize_t)size) {
		perror("Fatal: Failed to read random bytes");
		close(fd);
		exit(EXIT_FAILURE);
	}

	close(fd);
}

static mmap_alloc	map_file(char *filename, char **err_msg)
{
	mmap_alloc executable;

    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        vprintf_exit(ERR_STAT, err_msg, strerror(errno));
    }
    executable.size = st.st_size;

    executable.addr = mmap(NULL, executable.size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

    if (executable.addr == MAP_FAILED) {
        vprintf_exit(ERR_MMAP, err_msg, strerror(errno));
    }
    return executable;
}

mmap_alloc	encrypt_engine(parsing_info *info, char *filename, char **err_msg)
{
    // Map file in RAM
    mmap_alloc executable = map_file(filename, err_msg);

    // randomly generate the encryption key
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

    for (size_t i = 0; i < num_blocks; i++)
    {
        // Cipher directly inside memory
        xtea_encipher(32, &code_ptr[i * 2], xtea_key);
    }

    return executable;
    // create_woody(file_ptr, total_file_size, err_msg);
    // munmap(file_ptr, total_file_size);
}
