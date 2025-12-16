#include "../include/woody.h"

char	*get_payload(size_t *payload_size, bool is_64, char *file_buf, char *payload_path, char **err_msg)
{
	char *str = ft_substr(payload_path, 0, ft_strlen(payload_path) - ft_strlen("woody_woodpacker"));
	if (!str)
	{
		free(file_buf);
        vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
	}
	if (!is_64)
	{
		str = ft_strjoinfree(str, "Payload/payload32.bin", true, false);
		if (!str)
		{
			free(file_buf);
			vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
		}
	}
	else
	{
		str = ft_strjoinfree(str, "Payload/payload64.bin", true, false);
		if (!str)
		{
			free(file_buf);
			vprintf_exit(ERR_MALLOC, err_msg, strerror(errno));
		}
	}
	int fd = open(str, O_RDONLY);
	free(str);
    if (fd == -1) {
		free(file_buf);
        vprintf_exit(ERR_OPEN, err_msg, strerror(errno));
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
		free(file_buf);
        vprintf_exit(ERR_STAT, err_msg, strerror(errno));
    }
    *payload_size = st.st_size;

    void *ptr = mmap(NULL, payload_size, PROT_READ, 0, fd, 0);
    close(fd);

    if (ptr == MAP_FAILED)
	{
		free(file_buf);
        vprintf_exit(ERR_MMAP, err_msg, strerror(errno));
	}
	return ptr;
}

void	payload_insert32(char *file_buf, char *payload_path, char **err_msg)
{
	size_t	payload_size;
	char *payload_buff = get_payload(&payload_size, false, file_buf, payload_path, err_msg);

}