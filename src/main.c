#include "woody.h"

int main(int argc, char **argv)
{
	char	**err_msg = init_msgs();
    size_t total_file_size;

	if (argc == 1)
		vprintf_exit(ERR_HELP, err_msg);
	int fd = open(argv[1], O_RDWR);
	if (fd == -1)
		vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
	parsing_info parsing;
	parsing.encrypt = NULL;
	parsing.payload = NULL;
	parsing.is_64 = false;
	parse_elf(fd, &parsing, err_msg);
	free(parsing.payload);
	close(fd);
	encrypt_engine(parsing.encrypt, argv[1], err_msg, &total_file_size);
	free(parsing.encrypt);
	free_msg(err_msg);
}