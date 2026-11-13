#include "woody.h"

int main(int argc, char **argv)
{
	if (argc == 1) {
		print_message(HELP_MESSAGE);
		return 0;
	}
	int fd = open(argv[1], O_RDWR);
	error_if(fd == -1, ERR_OPEN, strerror(errno));
	parsing_info parsing = parse_elf(fd);
	close(fd);
	mmap_alloc executable = encrypt_engine(&parsing, argv[1]);
	payload_insert(&parsing, &executable);
}