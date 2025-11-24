#include "woody.h"

int main(int argc, char **argv)
{
	char	**err_msg = init_msgs();
	if (argc == 1)
		vprintf_exit(err_msg[ERR_HELP]);
	int fd = open(argv[1], O_RDWR);
	if (fd == -1)
		vprintf_exit(err_msg[ERR_OPEN], strerror(errno));
	parse_elf(fd, err_msg);
	close(fd);
}