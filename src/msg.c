#include "woody.h"

static void	assign_msg(int nbr, char* msg, char** msg_arr)
{
	msg_arr[nbr] = ft_strdup(msg);
	if (!msg_arr[nbr])
		vprintf_exit(NULL);
}

char	**init_msgs()
{
	char **err = malloc(sizeof(char*) * ERR_MAX);
	if (!err)
		vprintf_exit(NULL);
		
	assign_msg(ERR_HELP, "woody_packer: Invalid parameter: path to elf executable required\n", err);
	return err;
}

void	vprintf_exit(char *msg, ...)
{
	if (!msg)
	{
		printf("%s\n", strerror(errno));
		exit(1);
	}
	va_list args;
	va_start(args, msg);
	vprintf(msg, args);
	va_end(args);
	exit(1);
}
