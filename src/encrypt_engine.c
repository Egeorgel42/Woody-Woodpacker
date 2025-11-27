#include "woody.h"

#define KEY_SIZE 16
// 128 bits key = 16 bytes

void generate_random_key(uint8_t *buffer, size_t size)
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


void *map_file(char *filename, size_t *size, char **err_msg)
{
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
        return NULL;
    }

    // get file size
    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        vprintf_exit(ERR_READ, err_msg, strerror(errno));
        return NULL;
    }
    *size = st.st_size;

    // map da file
    void *ptr = mmap(NULL, *size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (ptr == MAP_FAILED) {
        close(fd);
        vprintf_exit(ERR_MALLOC, err_msg, strerror(errno)); // Mmap failed ~ alloc failed
        return NULL;
    }

    // mapping stays active until munmap
    close(fd);

    return ptr;
}

void encrypt_engine(encrypt_info *info, char **argv)
{
	uint8_t key_buffer[KEY_SIZE];

	generate_random_key(key_buffer, KEY_SIZE);
	printf("key_value: ");
	for (int i = 0; i < KEY_SIZE; i++) {
		printf("%02X", key_buffer[i]);
	}
	printf("\n");

	// Casting key_buffer for ciphering, as my ft take 32bits uint*
	uint32_t *xtea_key = (uint32_t *)key_buffer;

	// Get the data to encrypt
	size_t file_size;
	void *ptr = map_file(argv[1], &file_size, err_msg);

	xtea_encipher(32, placeholder_for_data, xtea_key);
}

