#include "../include/woody.h"

int main(int argc, char **argv)
{
	char	**err_msg = init_msgs();
	if (argc == 1)
		vprintf_exit(ERR_HELP, err_msg);
	int fd = open(argv[1], O_RDWR);
	if (fd == -1)
		vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
	encryt_info	*info = parse_elf(fd, err_msg);
	close(fd);
	free(info);
	free_msg(err_msg);
}