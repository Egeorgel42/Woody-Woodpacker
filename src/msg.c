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
		
	assign_msg(ERR_NEXEC, "woody_packer: Given parameter is not an elf file\n", err);
	assign_msg(ERR_NEXEC, "woody_packer: Given file is not an executable\n", err);
	assign_msg(ERR_OSABI, "woody_packer: Incompatible OS-ABI executable\n", err);
	assign_msg(ERR_ELFHDR, "woody_packer: Invalid Elf executable header\n", err);
	assign_msg(ERR_ENDIAN, "woody_packer: Big endian executables aren't supported\n", err);
	assign_msg(ERR_HELP, "woody_packer: Invalid parameter: path to elf executable required\n", err);
	assign_msg(ERR_READ, "woody_packer: Error during read of executable: %s\n", err);
	assign_msg(ERR_OPEN, "woody_packer: Error during open of executable: %s\n", err);
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
