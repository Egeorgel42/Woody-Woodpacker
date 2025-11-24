#include "woody.h"

int main(int argc, char **argv)
{
	char	**err_msg = init_msgs();
	if (argc == 1)
		vprintf_exit(err_msg[ERR_HELP]);
	(void)argv;
}