#include "woody.h"

int main(int argc, char **argv)
{
	char	**err_msg = init_msgs();

	if (argc == 1)
		vprintf_exit(ERR_HELP, err_msg);
	int fd = open(argv[1], O_RDWR);
	if (fd == -1)
		vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
	parsing_info parsing = parse_elf(fd, err_msg);
	close(fd);
	mmap_alloc executable = encrypt_engine(&parsing, argv[1], err_msg);
	payload_insert(&parsing, &executable, argv[0], err_msg);
	free_msg(err_msg);
}