#ifndef WOODY_H
# define WOODY_H
# include "../libft/libft.h"
# include <elf.h>
# include <stdio.h>
# include <unistd.h>
# include <errno.h>
# include <string.h>

typedef enum t_err {
	ERR_HELP,
	ERR_MAX
} msg_err;

char	**init_msgs();
void	vprintf_exit(char *msg, ...);

#endif